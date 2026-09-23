"""Corrupt derived observations cannot interrupt ordinary recovery or close work."""
import contextlib
import copy
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests import test_host_terminal_wire as wire
from tests.test_cg142_commentary import message

cg = wire.cg


class SidecarBoundaryTests(unittest.TestCase):
    def fixture(self):
        h = wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        h.start('Context Guard 是这个插件的名称吗？')
        event = message(turn=h.turn_id)
        event['payload']['thread_id'] = h.session_id
        h.rows.append(event)
        h.write_rows()
        directory = h.root / 'private/sessions' / h.session_id
        cg.dispatch(h.event('PreCompact'))
        self.assertEqual(cg.commentary_summary(directory,h.state())['status'],'observed')
        return h, directory, directory / 'commentary-observation.json'

    def assert_surfaces_unknown(self, h, directory):
        before = copy.deepcopy(h.state()['requirements'])
        delivery_before = copy.deepcopy(h.state().get('response_delivery'))
        for event, extra in (('PreCompact', {}), ('SessionStart', {'source':'compact'}),
                             ('SessionStart', {'source':'resume'})):
            cg.dispatch(h.event(event, **extra))
            self.assertEqual(h.state()['requirements'], before)
            self.assertEqual(h.state().get('response_delivery'), delivery_before)
            self.assertEqual(cg.commentary_summary(directory,h.state())['status'],'unknown')
        state = h.state()
        self.assertIn('answer coverage unknown', cg.status_context(state,session_dir=directory))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cg.command_status(),0)
        self.assertIn('answer coverage unknown',output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cg.command_diagnose(SimpleNamespace(limit=3)),0)
        self.assertEqual(json.loads(output.getvalue())['commentary_observation']['status'],'unknown')
        self.assertIn('answer coverage unknown', cg.diagnose_context(state,session_dir=directory))
        self.assertEqual(cg.checkpoint_status_snapshot(state,h.turn_id,session_dir=directory)
                         ['commentary_observation']['status'],'unknown')

    def test_parser_fault_family_across_recovery_and_views(self):
        invalid = (b'['*2000+b'0'+b']'*2000, b'\xff', b'[]', b'null', b'42', b'{',
                   b'{"schema":"x","schema":"y"}', b'{"value":NaN}',
                   b'{"value":"\\ud800"}')
        for value in invalid:
            with self.subTest(value=value[:24]):
                h, directory, path = self.fixture()
                path.write_bytes(value)
                self.assert_surfaces_unknown(h,directory)
                self.assertEqual(path.read_bytes(),value)

    def test_valid_digest_does_not_make_invalid_structure_trusted(self):
        for key,value in [('status', []), ('messages', {}), ('integrity_anchor', []),
                          ('watermark', {}), ('message_count', -1), ('file_identity', [])]:
            with self.subTest(key=key):
                h,directory,path = self.fixture()
                report = json.loads(path.read_text())
                report.pop('projection_sha256')
                report[key] = value
                report['projection_sha256'] = cg.sha256_text(cg.canonical_json(report))
                raw = json.dumps(report).encode()
                path.write_bytes(raw)
                self.assert_surfaces_unknown(h,directory)
                self.assertEqual(path.read_bytes(),raw)

    def test_unreadable_derived_file_does_not_mask_state_integrity(self):
        h,directory,path = self.fixture()
        original = cg.os.open
        def denied(target,*args,**kwargs):
            if wire.Path(target) == path:
                raise PermissionError('unreadable observation')
            return original(target,*args,**kwargs)
        with patch.object(cg.os,'open',denied):
            self.assert_surfaces_unknown(h,directory)
        state = h.state()
        state['integrity']['status'] = 'failed'
        for handler,extra in ((cg.handle_pre_compact,{}),
                              (cg.handle_session_start,{'source':'compact'}),
                              (cg.handle_session_start,{'source':'resume'})):
            with self.assertRaises(cg.StateIntegrityError):
                handler(directory,state,h.event('PreCompact',**extra))

    def test_nested_structure_and_duplicate_signed_fields_remain_unknown(self):
        for mutation in ('message_phase', 'message_questions', 'anchor_digest', 'duplicate', 'missing_snapshot', 'extra_message_field'):
            with self.subTest(mutation=mutation):
                h,directory,path = self.fixture()
                report = json.loads(path.read_text())
                report.pop('projection_sha256')
                if mutation == 'message_phase':
                    report['messages'][0]['phase'] = []
                elif mutation == 'message_questions':
                    report['messages'][0]['question_candidates'] = 42
                elif mutation == 'anchor_digest':
                    report['integrity_anchor']['snapshot_sha256'] = 'g'*64
                elif mutation == 'missing_snapshot':
                    del report['snapshot_sha256']
                elif mutation == 'extra_message_field':
                    report['messages'][0]['complete'] = True
                report['projection_sha256'] = cg.sha256_text(cg.canonical_json(report))
                raw = json.dumps(report).encode()
                if mutation == 'duplicate':
                    raw = raw[:-1] + b', "status": "observed"}'
                path.write_bytes(raw)
                self.assert_surfaces_unknown(h,directory)
                self.assertEqual(path.read_bytes(),raw)
