"""Observe later-turn Git identity; this mapping does not prove authorization."""
import json
import tempfile
import unittest
from pathlib import Path

from tests.test_host_raw_mapping import CAPTURE, MAPPING, Fixture


def mutate(fixture,sequence,**updates):
    fixture.mutate_raw(sequence,lambda raw:raw.update(updates))
    raw=(fixture.capture/f'capture-{sequence:06d}.raw').read_bytes()
    path=fixture.capture/f'capture-{sequence:06d}.meta.json'
    meta=json.loads(path.read_bytes())
    meta['wire']=CAPTURE.validate_wire(raw,meta['expected_event'])
    path.write_bytes(json.dumps(meta).encode())

class ResumedGitMappingTests(unittest.TestCase):
    def test_same_session_later_turn_binds_same_exact_git_object(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=Fixture(Path(temp))
            for sequence in (3,4):
                mutate(fixture,sequence,turn_id='later-push-turn')
            fixture.refresh_capture_report()
            bundle,receipt=fixture.adapt()
            self.assertEqual(bundle['session_id'],fixture.session)
            self.assertTrue(receipt)

    def test_later_turn_cannot_change_git_subject(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=Fixture(Path(temp))
            for sequence in (3,4):
                mutate(fixture,sequence,turn_id='later-push-turn')
            fixture.refresh_capture_report()
            fixture.mutate_manifest(lambda m:m['git'].update(final_head='f'*40))
            with self.assertRaisesRegex(MAPPING.MappingError,'readback'):
                fixture.adapt()

    def test_other_session_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=Fixture(Path(temp))
            for sequence in (3,4):
                mutate(fixture,sequence,session_id='other-session',turn_id='later-turn')
            fixture.refresh_capture_report()
            with self.assertRaises(MAPPING.MappingError):
                fixture.adapt()
