"""Independent expectations: review is revocable information, never execution."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_host_terminal_wire as wire
from tests.test_cg142_commentary import message

cg = wire.cg
review = cg.answer_review_module()


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.subject = {"session_id": "producer", "root_id": "P1", "question_id": "R1", "span_utf8": [0, 4], "root_sha256": "a" * 64, "question_sha256": "b" * 64, "turn_id": "t1"}
        self.messages = [{"message_id": "m1", "completed_at_ms": 2, "source_ordinal": 2}]
        self.authority = {"version": "1", "active": True}
        self.row = {"schema": review.SCHEMA, "id": "j1", "subject": self.subject,
                    "messages": self.messages, "authority": self.authority,
                    "result": {"verdict": "complete", "information_only": True, "message_ids": ["m1"], "associations": [{"message_id": "m1", "question_ids": ["R1"]}]},
                    "supersedes": [], "catalog": [self.subject],
                    "as_of": {"source": "codex-transcript-item-completed/v1", "snapshot_sha256": "c" * 64, "watermark": 10}}

    def coverage(self, rows=None, subject=None, messages=None, authority=None):
        return review.project(subject or self.subject, messages or self.messages,
                              [self.row] if rows is None else rows,
                              self.authority if authority is None else authority)["coverage"]

    def test_no_authority_and_revocation(self):
        self.assertEqual(self.coverage(authority={}), "unknown")
        self.assertEqual(self.coverage(authority={"version": "1", "active": False}), "unknown")
        self.assertEqual(self.coverage(authority={"version": "2", "active": True}), "unknown")

    def test_all_verdicts_and_execution_exclusion(self):
        for value in ("complete", "partial", "promise", "unknown"):
            self.row["result"]["verdict"] = value
            self.assertEqual(self.coverage(), value)
        self.row["result"].update(verdict="complete", information_only=False)
        self.assertEqual(self.coverage(), "unknown")

    def test_exact_question_isolation(self):
        for field, value in (("session_id", "other"), ("question_id", "R2"), ("span_utf8", [5, 9]), ("root_id", "P2")):
            self.assertEqual(self.coverage(subject={**self.subject, field: value}), "unknown")
        other = copy.deepcopy(self.row)
        other["subject"]["span_utf8"] = [5, 9]
        other["subject"]["question_id"] = "R2"
        other["result"]["verdict"] = "partial"
        self.assertEqual(self.coverage(rows=[self.row, other]), "complete")

    def test_id_conflict_and_replay(self):
        self.assertEqual(self.coverage(rows=[self.row, copy.deepcopy(self.row)]), "complete")
        changed = copy.deepcopy(self.row)
        changed["result"]["verdict"] = "partial"
        self.assertEqual(self.coverage(rows=[self.row, changed]), "unknown")

    def test_correction_late_parent_permutations_and_fork(self):
        correction = copy.deepcopy(self.row)
        correction.update(id="j2", supersedes=["j1"])
        correction["result"]["verdict"] = "partial"
        self.assertEqual(self.coverage(rows=[correction]), "unknown")
        for rows in ([self.row, correction], [correction, self.row]):
            self.assertEqual(self.coverage(rows=rows), "partial")
        fork = copy.deepcopy(correction)
        fork["id"] = "j3"
        self.assertEqual(self.coverage(rows=[self.row, correction, fork]), "unknown")

    def test_cycle_self_and_foreign_parent(self):
        for parent in ("j1", "missing"):
            self.row["supersedes"] = [parent]
            self.assertEqual(self.coverage(), "unknown")
        b = copy.deepcopy(self.row)
        b.update(id="j2", supersedes=["j1"])
        self.row["supersedes"] = ["j2"]
        self.assertEqual(self.coverage(rows=[self.row, b]), "unknown")

    def test_message_order_is_not_identifier_sorting(self):
        messages = [{"message_id": "z", "completed_at_ms": 2, "source_ordinal": 2}, {"message_id": "a", "completed_at_ms": 4, "source_ordinal": 3}]
        self.row["messages"] = messages
        self.row["result"]["message_ids"] = ["z", "a"]
        self.row["result"]["associations"] = [{"message_id": m["message_id"], "question_ids": ["R1"]} for m in messages]
        self.assertEqual(self.coverage(messages=messages), "complete")
        self.assertEqual(self.coverage(messages=list(reversed(messages))), "unknown")

    def test_unassessed_message_or_changed_identity(self):
        self.assertEqual(self.coverage(messages=[{"message_id": "m1", "completed_at_ms": 3}]), "unknown")
        self.assertEqual(self.coverage(messages=self.messages + [{"message_id": "m2"}]), "unknown")

    def test_invalid_response_and_extra_fields(self):
        for mutate in (lambda r: r.update(trusted=True),
                       lambda r: r["result"].update(verdict="yes"),
                       lambda r: r["result"].update(information_only=1),
                       lambda r: r["result"].update(message_ids=[])):
            row = copy.deepcopy(self.row)
            mutate(row)
            self.assertEqual(self.coverage(rows=[row]), "unknown")

    def test_strict_decode(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'[' * 2000, b'"\\ud800"'):
            with self.assertRaises((ValueError, RecursionError)):
                review.decode(raw)

    def test_dangling_ancestor_and_invalid_subject_are_unknown(self):
        b = copy.deepcopy(self.row)
        b.update(id="j2", supersedes=["missing"])
        self.row["supersedes"] = ["j2"]
        self.assertEqual(self.coverage(rows=[self.row, b]), "unknown")
        for span in ([True, 4], [4, 0], [0], [-1, 2]):
            self.assertEqual(self.coverage(subject={**self.subject, "span_utf8": span}), "unknown")

    def test_untrusted_authority_cannot_override(self):
        other = copy.deepcopy(self.row)
        other.update(id="untrusted", authority={"active": True, "version": "self"})
        other["result"]["verdict"] = "partial"
        self.assertEqual(self.coverage(rows=[self.row, other]), "complete")


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.host = wire.HostTerminalWireTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        h = self.host
        cg.dispatch(h.event('UserPromptSubmit', prompt='context-guard on'))
        h.turn_id = 'question-turn'
        cg.dispatch(h.event('UserPromptSubmit', prompt='Context Guard 是这个插件的名称吗？'))
        item = message(turn=h.turn_id)
        item['payload']['thread_id'] = h.session_id
        h.rows.append(item)
        h.write_rows()
        self.directory = h.root / 'private/sessions' / h.session_id
        self.state = h.state()
        self.item = self.state['requirements'][-1]
        prepare_source = getattr(self, 'prepare_commentary_source', None)
        if prepare_source is not None:
            prepare_source()
        self.request = cg.answer_review_request(self.directory, self.state, self.item)
        self.reviews = self.directory / 'answer-reviews'
        self.binary = h.root / 'fixture-binary'
        self.binary.write_bytes(b'fixture, never executed')
        self.binary_hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.configure(self.reviews, 'fixture-v1')

    def configure(self, directory, version):
        directory.mkdir(parents=True, exist_ok=True)
        review.exclusive(directory / 'policy.json', {'version': version, 'active': True,
                         'binary': str(self.binary), 'binary_sha256': self.binary_hash})

    def stdout(self, verdict='complete', session='separate-reviewer'):
        output = {"verdict": verdict, "information_only": True,
                  "message_ids": [m['message_id'] for m in self.request['messages']],
                  "associations": [{"message_id": m["message_id"], "question_ids": [self.request["subject"]["question_id"]]} for m in self.request["messages"]]}
        return '\n'.join(json.dumps(r) for r in (
            {'type': 'thread.started', 'thread_id': session}, {'type': 'turn.started'},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': json.dumps(output)}},
            {'type': 'turn.completed'}))

    def collect(self, verdict='complete', supersedes=()):
        with patch.object(review, 'invoke', return_value=subprocess.CompletedProcess([], 0, self.stdout(verdict), '')) as run:
            identity = review.collect(self.reviews, self.request, self.binary, self.binary_hash, 'fixture-v1',
                                      execute=True, supersedes=supersedes)
            self.assertEqual(run.call_count, 1)
        return identity

    def test_real_scope_consumer_and_compact_resume_without_state_mutation(self):
        before = copy.deepcopy(self.state)
        self.collect()
        scope = cg.current_scope_projection(self.state)
        self.assertNotIn(self.item['id'], scope['current_item_ids'])
        self.assertEqual(scope['answer_reviews'][self.item['id']]['coverage'], 'complete')
        self.assertEqual(self.state, before)
        for kind, extra in [('PreCompact', {}), ('SessionStart', {'source': 'compact'}), ('SessionStart', {'source': 'resume'})]:
            cg.dispatch(self.host.event(kind, **extra))
            self.assertNotIn(self.item['id'], cg.current_scope_projection(self.host.state())['current_item_ids'])
        self.assertEqual(self.host.state()['requirements'], before['requirements'])

    def test_correction_and_revocation_reopen_only_information(self):
        first = self.collect()
        self.collect('partial', supersedes=[first])
        self.assertIn(self.item['id'], cg.current_scope_projection(self.state)['current_item_ids'])
        policy = review.read(self.reviews / 'policy.json')
        policy['active'] = False
        (self.reviews / 'policy.json').write_bytes(review.canonical(policy))
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')

    def test_cold_load_rejects_missing_or_tampered_source(self):
        identity = self.collect()
        path = self.reviews / ('capture-' + identity + '.json')
        capture = review.read(path)
        capture['payload']['record']['result']['verdict'] = 'partial'
        path.write_bytes(review.canonical(capture))
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')
        path.unlink()
        self.assertIn(self.item['id'], cg.current_scope_projection(self.state)['current_item_ids'])

    def test_producer_self_review_tools_failed_and_timeout(self):
        for stdout, code in ((self.stdout(session=self.host.session_id), 0),
                             (self.stdout() + '\n' + json.dumps({'type': 'item.started', 'item': {'type': 'command_execution'}}), 0),
                             (self.stdout(), 1)):
            with tempfile.TemporaryDirectory() as root:
                self.configure(Path(root), 'fixture')
                with patch.object(review, 'invoke', return_value=subprocess.CompletedProcess([], code, stdout, '')):
                    with self.assertRaises(ValueError):
                        review.collect(Path(root), self.request, self.binary, self.binary_hash, 'fixture', execute=True)
        with patch.object(review, 'invoke', side_effect=ValueError('review_timeout')):
            with self.assertRaises(ValueError):
                review.collect(self.reviews, self.request, self.binary, self.binary_hash, 'fixture-v1', execute=True)

    def test_no_execute_or_wrong_binary_never_calls(self):
        with patch.object(review, 'invoke') as run:
            for execute, digest in ((False, self.binary_hash), (True, '0' * 64)):
                with self.assertRaises(ValueError):
                    review.collect(self.reviews, self.request, self.binary, digest, 'v1', execute=execute)
            run.assert_not_called()

    def test_business_item_and_wait_unchanged(self):
        self.collect()
        other = copy.deepcopy(self.item)
        other.update(id='R999', text='请修改文件。', execution_kind='local_edit')
        self.state['requirements'].append(other)
        before = copy.deepcopy(self.state)
        cg.current_scope_projection(self.state)
        self.assertEqual(self.state, before)
        with self.assertRaises(ValueError):
            cg.answer_review_request(self.directory, self.state, other)

    def test_followup_and_other_root_do_not_invalidate_old_question(self):
        self.collect()
        h = self.host
        h.turn_id = 'second-question'
        cg.dispatch(h.event('UserPromptSubmit', prompt='Context Guard 是开源软件吗？'))
        event = message(mid='m2', turn=h.turn_id)
        event['payload']['thread_id'] = h.session_id
        h.rows.append(event)
        h.write_rows()
        state = h.state()
        scope = cg.current_scope_projection(state)
        self.assertEqual(scope['answer_reviews'][self.item['id']]['coverage'], 'complete')
        self.assertNotEqual(scope['answer_reviews'][state['requirements'][-1]['id']]['coverage'], 'complete')

    def test_authority_version_and_adapter_changes_invalidate_cold_replay(self):
        self.collect()
        path = self.reviews / 'policy.json'
        policy = review.read(path)
        policy['version'] = 'revoked-version'
        path.write_bytes(review.canonical(policy))
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')

    def test_raw_source_change_and_missing_turn_fail_closed(self):
        self.collect()
        self.host.rows[-1]['payload']['item']['content'][0]['text'] = 'Correction: unknown.'
        self.host.write_rows()
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')

    def test_review_event_order_and_extra_turn_are_rejected(self):
        lines = self.stdout().splitlines()
        for candidate in (lines[1:] + lines[:1], lines[:1] + lines[2:], lines + [lines[1]],
                          lines[:2] + [lines[1]] + lines[2:]):
            with self.assertRaises(ValueError):
                review.parse_output('\n'.join(candidate), self.host.session_id)

    def test_unconfigured_reviewer_cannot_adopt_its_own_binary(self):
        (self.reviews / 'policy.json').unlink()
        with patch.object(review, 'invoke') as run:
            with self.assertRaises(ValueError):
                review.collect(self.reviews, self.request, self.binary, self.binary_hash, 'self', execute=True)
            run.assert_not_called()

    def test_signed_capture_with_inconsistent_source_text_is_unknown(self):
        identity = self.collect()
        path = self.reviews / ('capture-' + identity + '.json')
        value = review.read(path)
        value['payload']['request']['question_text'] = 'different'
        # A collector bug that seals inconsistent inputs still cannot close.
        value['mac'] = review.seal(value['payload'], (self.reviews / 'capture.key').read_bytes())
        path.write_bytes(review.canonical(value))
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')

    def test_missing_key_is_unknown_after_cold_load(self):
        self.collect()
        (self.reviews / 'capture.key').unlink()
        self.assertIn(self.item['id'], cg.current_scope_projection(self.host.state())['current_item_ids'])

    def test_unknown_and_promise_never_discharge(self):
        first = self.collect('promise')
        self.assertIn(self.item['id'], cg.current_scope_projection(self.state)['current_item_ids'])
        self.collect('unknown', supersedes=[first])
        self.assertIn(self.item['id'], cg.current_scope_projection(self.state)['current_item_ids'])

    def test_constraint_and_proof_are_not_reviewable(self):
        for extra in ({'constraint_scope': 'session'}, {'verification_contract': {'mode': 'enforced'}}):
            with self.assertRaises(ValueError):
                cg.answer_review_request(self.directory, self.state, {**self.item, **extra})

    def test_completed_or_superseded_state_not_revived(self):
        self.collect()
        for status in ('answered', 'superseded', 'pass'):
            self.item['status'] = status
            before = copy.deepcopy(self.state)
            cg.reviewed_information(self.state)
            self.assertEqual(self.state, before)

    def test_source_snapshot_disappearance_is_unknown(self):
        self.collect()
        self.host.transcript.unlink()
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')

    def test_new_same_question_message_requires_new_judgment(self):
        self.collect()
        event = message(mid='m2', turn=self.host.turn_id, text='Correction: earlier answer incomplete.')
        event['payload'].update(thread_id=self.host.session_id, started_at_ms=3, completed_at_ms=4)
        self.host.rows.append(event)
        self.host.write_rows()
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')

    def test_revocation_tombstone_prevents_reusing_old_authority(self):
        self.collect()
        review.revoke(self.reviews)
        self.assertEqual(cg.reviewed_information(self.state)[self.item['id']]['coverage'], 'unknown')
        with self.assertRaises(ValueError):
            self.collect()

    def test_process_transport_capability_boundary(self):
        if review.os.name not in {"posix", "nt"}:
            with self.assertRaises(ValueError):
                review.invoke([sys.executable, "-c", "pass"], "")
            return
        result = review.invoke([sys.executable, '-c', 'import sys; print(sys.stdin.read())'], 'fixture')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), 'fixture')
        with self.assertRaises(ValueError):
            review.invoke([sys.executable, '-c', 'print("x" * 3000000)'], '')
