"""R12 independent transcript-domain and display-limit holdouts."""
import unittest

from tests import test_answer_review as base


class SourceDomainTests(unittest.TestCase):
    setUp = base.ConsumerTests.setUp
    configure = base.ConsumerTests.configure
    stdout = base.ConsumerTests.stdout
    collect = base.ConsumerTests.collect

    def test_finite_float_metadata_does_not_reopen_answer(self):
        self.collect()
        self.host.rows.append({'type': 'unrelated_record', 'payload': {'duration_seconds': 0.25}})
        self.host.write_rows()
        self.assertNotIn(self.item['id'], base.cg.current_scope_projection(self.host.state())['current_item_ids'])

    def test_real_record_families_accept_finite_numeric_metadata(self):
        import json
        original = list(self.host.rows)
        self.collect()
        records = [
            {'type': 'turn_context', 'payload': {'sampling': {'temperature': 0.25, 'weights': [1.0, 1e-8]}}},
            {'type': 'event_msg', 'payload': {'type': 'token_count', 'rate_limits': {'used_percent': 12.5}}},
            {'type': 'response_item', 'payload': {'type': 'function_call_output', 'metadata': {'duration_seconds': 0.25}}},
            {'type': 'event_msg', 'payload': {'type': 'task_complete', 'elapsed': 1e100}},
        ]
        for row in records:
            with self.subTest(record=row['type']):
                self.host.rows = original + [row]
                self.host.write_rows()
                self.assertNotIn(self.item['id'], base.cg.current_scope_projection(self.host.state())['current_item_ids'])
        for literal in ('1e-3', '2.5E+2', '1e308', '-0.0'):
            self.host.rows = original
            self.host.write_rows()
            with self.host.transcript.open('ab') as stream:
                stream.write(('{"type":"turn_context","payload":{"nested":{"duration":' + literal + '}}}\n').encode())
            self.assertNotIn(self.item['id'], base.cg.current_scope_projection(self.host.state())['current_item_ids'])
        # The receipt domain stays deliberately narrower.
        with self.assertRaises(ValueError):
            base.review.decode(json.dumps({'elapsed': 0.25}).encode())

    def test_invalid_json_resources_and_message_types_still_fail_closed(self):
        original = self.host.transcript.read_bytes()
        self.collect()
        malformed = [
            b'{"type":"turn_context","payload":{"a":1,"a":2}}\n',
            b'{"type":"turn_context","payload":{"x":NaN}}\n',
            b'{"type":"turn_context","payload":{"x":Infinity}}\n',
            b'{"type":"turn_context","payload":{"x":1e999}}\n',
            b'{"type":"turn_context","payload":"\\ud800"}\n',
            b'{"type":"turn_context","payload":' + b'[' * 40 + b'0' + b']' * 40 + b'}\n',
        ]
        for raw in malformed:
            self.host.transcript.write_bytes(original + raw)
            scope = base.cg.current_scope_projection(self.host.state())
            self.assertIn(self.item['id'], scope['current_item_ids'])
        self.host.rows[-1]['payload']['completed_at_ms'] = 2.0
        self.host.write_rows()
        self.assertIn(self.item['id'], base.cg.current_scope_projection(self.host.state())['current_item_ids'])

    def append_history(self, count, padding=''):
        import json
        with self.host.transcript.open('ab') as stream:
            for i in range(count):
                row = base.message(mid=f'history-{i}', turn='historical-turn', text='history' + padding)
                row['payload'].update(thread_id=self.host.session_id, started_at_ms=100 + i * 2,
                                      completed_at_ms=101 + i * 2)
                stream.write((json.dumps(row) + '\n').encode())

    def test_982_message_large_snapshot_reviews_root_outside_display_window(self):
        self.collect()
        self.append_history(981, 'x' * 160000)
        state = self.host.state()
        observed = base.cg.commentary_observation(self.directory, state, self.host.event('PreCompact'))
        self.assertEqual(observed['message_count'], 982)
        self.assertEqual(len(observed['messages']), 512)
        self.assertNotIn('m1', [m['message_id'] for m in observed['messages']])
        request = base.cg.answer_review_request(self.directory, state, self.item)
        self.assertEqual([m['message_id'] for m in request['messages']], ['m1'])
        self.assertEqual(set(request['answer_texts']), {'m1'})
        self.assertNotIn(self.item['id'], base.cg.current_scope_projection(state)['current_item_ids'])

    def test_conflict_in_unselected_history_still_invalidates_full_file(self):
        import json
        self.collect()
        self.append_history(600)
        conflict = base.message(mid='history-0', turn='historical-turn', text='conflicting text')
        conflict['payload'].update(thread_id=self.host.session_id, started_at_ms=100, completed_at_ms=101)
        with self.host.transcript.open('ab') as stream:
            stream.write((json.dumps(conflict) + '\n').encode())
        self.assertIn(self.item['id'], base.cg.current_scope_projection(self.host.state())['current_item_ids'])

    def test_relevant_message_count_overflow_does_not_block_other_root(self):
        import json
        self.collect()
        h = self.host
        old_id = self.item['id']
        h.turn_id = 'second-root'
        base.cg.dispatch(h.event('UserPromptSubmit', prompt='Context Guard 是开源软件吗？'))
        item = h.state()['requirements'][-1]
        row = base.message(mid='new-root-message', turn=h.turn_id)
        row['payload'].update(thread_id=h.session_id, started_at_ms=10, completed_at_ms=11)
        with h.transcript.open('ab') as stream:
            stream.write((json.dumps(row) + '\n').encode())
            for i in range(513):
                extra = base.message(mid=f'overflow-{i}', turn=self.request['subject']['turn_id'])
                extra['payload'].update(thread_id=h.session_id, started_at_ms=100 + i*2, completed_at_ms=101 + i*2)
                stream.write((json.dumps(extra) + '\n').encode())
        state = h.state()
        source = base.cg.answer_review_source(self.directory, state)
        self.assertIn(self.request['subject']['root_id'], source['overflow_roots'])
        request = base.cg.answer_review_request(self.directory, state, item, source=source)
        self.assertEqual([m['message_id'] for m in request['messages']], ['new-root-message'])
        result = base.cg.reviewed_information(state)
        self.assertEqual(result[old_id]['coverage'], 'unknown')

    def test_relevant_text_budget_is_not_silently_truncated(self):
        import json
        self.collect()
        with self.host.transcript.open('ab') as stream:
            for i in range(3):
                row = base.message(mid=f'long-{i}', turn=self.host.turn_id, text='x' * 800000)
                row['payload'].update(thread_id=self.host.session_id, started_at_ms=10 + 2*i, completed_at_ms=11 + 2*i)
                stream.write((json.dumps(row) + '\n').encode())
        source = base.cg.answer_review_source(self.directory, self.host.state())
        self.assertIn(self.request['subject']['root_id'], source['overflow_roots'])
        self.assertEqual(source['answer_texts'], {})
        with self.assertRaisesRegex(ValueError, 'budget_exceeded'):
            base.cg.answer_review_request(self.directory, self.host.state(), self.item, source=source)
