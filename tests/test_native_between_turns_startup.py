"""Default provider readback and owned client cleanup regression coverage."""

import io
import queue
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import native_between_turns_acceptance as bt


class StartupAndCleanupTests(unittest.TestCase):
    def test_provider_default_and_overrides(self):
        for selector in (None, 'openai'):
            actual = bt.provider_projection({'config': {'model_provider': selector, 'model_providers': {'other': {}}}})
            self.assertIs(actual['model_provider'], selector)
        for config in ({'model_providers': {}},
                       {'model_provider': 'other', 'model_providers': {}},
                       {'model_provider': 0, 'model_providers': {}},
                       {'model_provider': None, 'model_providers': None},
                       {'model_provider': None, 'model_providers': {'openai': {}}},
                       {'model_provider': None, 'model_providers': {}, 'openai_base_url': 'https://example.invalid'},
                       {'model_provider': None, 'model_providers': {}, 'model_catalog_json': 'custom'}):
            with self.subTest(config=config), self.assertRaises(bt.Refused):
                bt.provider_projection({'config': config})

    def build(self, root, *, fail_rpc=False, spawn_exc=None, owned_receipt=None, close_exc=None):
        class Base:
            def rpc(self, method, params):
                if fail_rpc:
                    raise RuntimeError('fixture')
                if method == 'config/read':
                    return {'config': {'model_provider': None, 'model_providers': {}}}
                return {}
            def send(self, message):
                pass
        process = types.SimpleNamespace(pid=4242, stdin=io.StringIO(), stdout=io.StringIO(''))
        receipt = owned_receipt or {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                                    'process_group_cleanup_error': None}
        class Owner:
            def __init__(self):
                self.process = process
            def close(self, timeout):
                if close_exc:
                    raise close_exc
                return receipt
        class Tree:
            @staticmethod
            def spawn(*args, **kwargs):
                if spawn_exc:
                    raise spawn_exc
                return Owner()
        ctx = {'u': types.SimpleNamespace(UpgradeClient=Base),
               'host': types.SimpleNamespace(OwnedProcess=Tree, Client=Base),
               'output': root, 'old_root': root, 'home': root, 'cli': root / 'cli',
               'workspace': root, 'expected_model': 'test-model', 'read_file': root / 'README.md'}
        return ctx, process

    @mock.patch.object(bt.platform, "system", return_value="Darwin")
    def test_normal_and_startup_failure_cleanup(self, _platform):
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                ctx, process = self.build(Path(tmp), fail_rpc=failure)
                with mock.patch.object(bt, 'product_inventory', return_value={}):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            bt.DailyClientFactory(ctx)()
                        receipt = ctx['startup_cleanup']
                    else:
                        client = bt.DailyClientFactory(ctx)()
                        receipt = client.close()
                self.assertTrue(bt.client_cleanup_confirmed(receipt), receipt)
                self.assertTrue(process.stdin.closed and process.stdout.closed)
                self.assertTrue(receipt['reader_stopped'])

    def test_spawn_failure_receipts_fail_closed(self):
        class Failure(Exception):
            pass
        clean = {'process_created': False, 'cleanup_complete': True,
                 'process_group_cleanup_error': None, 'cleanup_errors': [],
                 'job_close_confirmed': True, 'job_assignment_confirmed': False,
                 'process_group_signal_denied': False, 'process_group_query_denied': False}
        for underlying, accepted in [(clean, True),
                                     ({**clean, 'process_creation_unknown': True}, False),
                                     ({**clean, 'job_close_confirmed': False}, False),
                                     ({**clean, 'process_group_cleanup_error': 'failed'}, False),
                                     ({**clean, 'cleanup_errors': ['failed']}, False),
                                     ({**clean, 'process_group_signal_denied': True}, False),
                                     ({**clean, 'process_created': True, 'owned_process_exited': True,
                                       'owned_tree_no_running_members': True}, False),
                                     ({'cleanup_complete': False}, False), (None, False)]:
            with self.subTest(receipt=underlying), tempfile.TemporaryDirectory() as tmp:
                exc = Failure()
                if underlying is not None:
                    exc.cleanup = underlying
                ctx, _ = self.build(Path(tmp), spawn_exc=exc)
                with mock.patch.object(bt.platform, 'system', return_value='Windows'):
                    with self.assertRaises(Failure):
                        bt.DailyClientFactory(ctx)()
                self.assertIs(ctx['startup_cleanup']['client_cleanup_complete'], accepted)

    @mock.patch.object(bt.platform, "system", return_value="Darwin")
    def test_cleanup_cancellation_is_propagated_after_closing_io(self, _platform):
        for kind in (KeyboardInterrupt, SystemExit):
            for valid in (True, False):
                with self.subTest(kind=kind, valid=valid), tempfile.TemporaryDirectory() as tmp:
                    ctx, process = self.build(Path(tmp))
                    with mock.patch.object(bt, 'product_inventory', return_value={}):
                        client = bt.DailyClientFactory(ctx)()
                    exc = kind()
                    exc.cleanup = {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                                   'process_group_cleanup_error': None, 'cleanup_complete': valid}
                    def interrupted(timeout):
                        raise exc
                    client.owned.close = interrupted
                    with self.assertRaises(kind) as caught:
                        client.close()
                    self.assertIs(caught.exception, exc)
                    self.assertTrue(process.stdin.closed and process.stdout.closed)
                    self.assertIs(caught.exception.cleanup['client_cleanup_complete'], valid)

    @mock.patch.object(bt.platform, "system", return_value="Darwin")
    def test_cancellation_during_startup_cleanup_propagates(self, _platform):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                exc = kind()
                exc.cleanup = {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                               'process_group_cleanup_error': None}
                ctx, process = self.build(Path(tmp), fail_rpc=True, close_exc=exc)
                with self.assertRaises(kind) as caught:
                    bt.DailyClientFactory(ctx)()
                self.assertIs(caught.exception, exc)
                self.assertTrue(process.stdin.closed and process.stdout.closed)
                self.assertTrue(ctx['startup_cleanup']['client_cleanup_complete'])

    def test_explicit_false_and_component_failure(self):
        base = {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                'process_group_cleanup_error': None, 'client_cleanup_complete': True,
                'reader_started': True, 'reader_stopped': True,
                'io_closed': {'stdin': True, 'stdout': True, 'log': True, 'err': True}}
        with mock.patch.object(bt.platform, 'system', return_value='Darwin'):
            self.assertTrue(bt.client_cleanup_confirmed(base))
            for change in ({'cleanup_complete': False}, {'cleanup_complete': None}, {'cleanup_complete': 0},
                           {'cleanup_complete': 'unknown'}, {'process_creation_unknown': None},
                           {'process_creation_unknown': 'unknown'}, {'reader_stopped': False}, {'reader_started': False},
                           {'io_closed': {**base['io_closed'], 'stdout': False}},
                           {'process_creation_unknown': True}):
                self.assertFalse(bt.client_cleanup_confirmed({**base, **change}))

    def test_reader_full_queue_returns_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx, process = self.build(Path(tmp))
            with mock.patch.object(bt, 'product_inventory', return_value={}):
                client = bt.DailyClientFactory(ctx)()
            try:
                process.stdout = io.StringIO('{"x": 1}\n')
                client.q = queue.Queue(maxsize=1)
                client.q.put({})
                client.reader()
                self.assertEqual(client.reader_failure, 'queue_full')
            finally:
                client.close()

if __name__ == '__main__':
    unittest.main()
