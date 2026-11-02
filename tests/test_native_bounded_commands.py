"""Bounded command wrapper owns, cleans and reports its synthetic children."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tools.validation import native_acceptance as native


class NativeBoundedCommands(unittest.TestCase):
    def test_success_failure_and_timeout(self):
        root = Path(__file__).resolve().parents[1]
        success = native.run(root, sys.executable, '-c', 'print("ok")')
        self.assertEqual(success.stdout.strip(), 'ok')
        with self.assertRaises(native.NativeRunError):
            native.run(root, sys.executable, '-c', 'raise SystemExit(7)')
        with patch.object(native, 'COMMAND_TIMEOUT_SECONDS', 0.2):
            with self.assertRaisesRegex(native.NativeRunError, 'TimeoutExpired'):
                native.run(root, sys.executable, '-c', 'import time; time.sleep(10)')

    def test_unknown_process_cleanup_fails_closed(self):
        process = Mock()
        process.communicate.return_value = ('', '')
        process.stdout = process.stderr = None
        owner = Mock(process=process)
        owner.close.return_value = {'owned_process_exited': True,
                                    'owned_tree_no_running_members': False,
                                    'process_group_cleanup_error': None}
        module = SimpleNamespace(OwnedProcess=SimpleNamespace(spawn=lambda *a, **k: owner),
                                 ProcessTreeError=ValueError)
        with patch.object(native, 'load_process_tree', return_value=module):
            with self.assertRaises(native.ProcessCleanupUnknown):
                native.run(Path('.'), 'synthetic')

    def test_surviving_child_is_not_success_even_if_leader_exits_zero(self):
        root = Path(__file__).resolve().parents[1]
        program = ('import subprocess,sys; '
                   'subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"], '
                   'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)')
        with self.assertRaisesRegex(native.NativeRunError, 'natural completion'):
            native.run(root, sys.executable, '-c', program)


if __name__ == '__main__':
    unittest.main()
