"""Byte-preserving JSON fragment coalescing and unchanged atomic publication."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_cg122_p0_counterexamples import cg


class JsonAtomicEncodingTests(unittest.TestCase):
    def test_exact_encoder_bytes_across_json_domain(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Float(float):
            pass

        values = [None, True, False, '', Text('中🚀\n\r\t\x00"\\'),
                  10**100, Integer(-4), Float(-0.0), float('nan'),
                  float('inf'), float('-inf'), [], {}, (),
                  {None: None, True: 1, 2: False, 3.25: [1, 2]},
                  {'ordered': {'b': 1, 'a': 2}, 'tuple': (True, None)},
                  {'rows': [{'id': i, 'text': '中🚀\n' + str(i),
                             'nested': [None, True, -0.0]} for i in range(500)]},
                  {'rows': [{'id': i, 'text': 'ascii-' + str(i)}
                            for i in range(500)]}]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'state.json'
            for value in values:
                with self.subTest(kind=type(value).__name__):
                    expected = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
                    cg.atomic_write_json(target, value)
                    self.assertEqual(target.read_bytes(), expected)
                    if os.name != 'nt':
                        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_encoding_failures_precede_any_filesystem_change(self):
        cyclic = []
        cyclic.append(cyclic)
        values = [object(), {(): 'invalid key'}, cyclic,
                  [{'valid': i} for i in range(500)] + [object()]]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'not-created' / 'state.json'
            for value in values:
                with self.subTest(kind=type(value).__name__):
                    try:
                        json.dumps(value, ensure_ascii=False, indent=2)
                    except (TypeError, ValueError) as expected:
                        with mock.patch.object(cg, 'atomic_write_text') as writer, \
                                mock.patch.object(cg, 'secure_directory') as secure:
                            with self.assertRaises(type(expected)) as actual:
                                cg.atomic_write_json(target, value)
                            self.assertEqual(str(actual.exception), str(expected))
                            writer.assert_not_called()
                            secure.assert_not_called()
                    else:
                        self.fail('negative fixture unexpectedly encodes')
            self.assertFalse(target.parent.exists())

    def test_encoding_failure_preserves_existing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'state.json'
            target.write_bytes(b'old state')
            for value in (object(), {'bad': '\ud800'}):
                with self.subTest(kind=type(value).__name__):
                    with self.assertRaises((TypeError, UnicodeEncodeError)):
                        cg.atomic_write_json(target, value)
                    self.assertEqual(target.read_bytes(), b'old state')
                    self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_fsync_and_replace_failure_preserve_target_and_clean_temp(self):
        for stage in ('fsync', 'replace'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / 'state.json'
                target.write_bytes(b'old state')
                with mock.patch.object(cg.os, stage, side_effect=OSError(stage)):
                    with self.assertRaisesRegex(OSError, stage):
                        cg.atomic_write_json(target, {'new': '中🚀'})
                self.assertEqual(target.read_bytes(), b'old state')
                self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_committed_windows_json_uses_original_publisher_and_no_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'state.json'
            target.write_bytes(b'old state')
            with mock.patch.object(cg, 'os', wraps=os) as platform, \
                    mock.patch.object(cg, '_replace_windows_committed_state',
                                      side_effect=PermissionError('denied')) as publisher, \
                    mock.patch.object(cg, '_harden_private_directory_windows',
                                      side_effect=lambda p: os.chmod(p, 0o700)):
                platform.name = 'nt'
                with self.assertRaisesRegex(PermissionError, 'denied'):
                    cg.atomic_write_json(target, {'new': '中🚀'}, committed_state=True)
                publisher.assert_called_once()
                platform.fsync.assert_called_once()
                platform.replace.assert_not_called()
            self.assertEqual(target.read_bytes(), b'old state')
            self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_commit_option_call_contract_unchanged(self):
        target = Path('unused.json')
        with mock.patch.object(cg, 'atomic_write_text') as writer:
            cg.atomic_write_json(target, {'a': 1})
            writer.assert_called_once_with(target, '{\n  "a": 1\n}\n')
            writer.reset_mock()
            cg.atomic_write_json(target, {'a': 1}, committed_state=True)
            writer.assert_called_once_with(target, '{\n  "a": 1\n}\n', committed_state=True)


if __name__ == '__main__':
    unittest.main()
