"""Fail-closed source oracles for the bounded official-host collector."""
import copy
import unittest

from tools.validation import stop_host_acceptance as h


class HostOracleTests(unittest.TestCase):
    def test_state_snapshot_resolves_v2_and_preserves_legacy_replay(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / 'sessions/t/state.json'
            old.parent.mkdir(parents=True)
            old.write_text('{}')
            self.assertEqual(h.session_state_path(root, 't'), old)
            new = root / 'sessions-v2/t/state.json'
            new.parent.mkdir(parents=True)
            new.write_text('{}')
            self.assertEqual(h.session_state_path(root, 't'), new)

    def inventory(self, event='stop'):
        return {event: {'key': 'product:' + event, 'eventName': event,
                       'sourcePath': '/cache/hooks.json', 'source': 'plugin',
                       'handlerType': 'command', 'displayOrder': 8, 'async': False}}

    def rows(self, statuses=('blocked', 'completed')):
        rows = []
        for status in statuses:
            run = {'id': 'stop:8', 'eventName': 'stop', 'sourcePath': '/cache/hooks.json',
                   'status': 'running', 'durationMs': None, 'source': 'plugin',
                   'handlerType': 'command', 'displayOrder': 8, 'executionMode': 'sync'}
            for method in ('hook/started', 'hook/completed'):
                current = dict(run)
                if method == 'hook/completed':
                    current.update(status=status, durationMs=400)
                rows.append({'method': method, 'params': {
                    'threadId': 't', 'turnId': 'u', 'run': current}})
        return rows

    def test_sequential_same_handler_is_two_runs(self):
        self.assertEqual([x['status'] for x in h.hook_runs(self.rows(), 't', 'u', self.inventory())],
                         ['blocked', 'completed'])

    def test_missing_pair_wrong_scope_source_failure_and_timeout(self):
        for mutate in ('missing_start', 'missing_end', 'source', 'event',
                       'failed', 'no_duration', 'timeout', 'wrong_turn', 'overlap'):
            with self.subTest(mutate=mutate):
                rows = self.rows(('completed',))
                if mutate == 'missing_start':
                    rows.pop(0)
                elif mutate == 'missing_end':
                    rows.pop()
                elif mutate == 'source':
                    rows[-1]['params']['run']['sourcePath'] = '/wrong'
                elif mutate == 'event':
                    rows[-1]['params']['run']['eventName'] = 'preCompact'
                elif mutate == 'failed':
                    rows[-1]['params']['run']['status'] = 'failed'
                elif mutate == 'no_duration':
                    rows[-1]['params']['run']['durationMs'] = None
                elif mutate == 'timeout':
                    rows[-1]['params']['run']['durationMs'] = 10000
                elif mutate == 'wrong_turn':
                    rows[-1]['params']['turnId'] = 'other'
                elif mutate == 'overlap':
                    rows.insert(1, copy.deepcopy(rows[0]))
                with self.assertRaises(ValueError):
                    h.hook_runs(rows, 't', 'u', self.inventory())

    def test_coherent_foreign_source_or_handler_is_rejected(self):
        for field, value in [('sourcePath', '/other/hooks.json'), ('source', 'user'),
                             ('handlerType', 'mcpTool'), ('displayOrder', 0),
                             ('executionMode', 'async')]:
            rows = self.rows(('completed',))
            for row in rows:
                row['params']['run'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.hook_runs(rows, 't', 'u', self.inventory())

    def compact_rows(self):
        hs = self.rows(('completed',))
        for row in hs:
            row['params']['run']['eventName'] = 'preCompact'
        start = {'method': 'turn/started', 'params': {'threadId': 't', 'turn': {'id': 'u'}}}
        items = [{'method': 'item/' + kind, 'params': {'threadId': 't', 'turnId': 'u',
                  'item': {'id': 'compact-one', 'type': 'contextCompaction'}}}
                 for kind in ('started', 'completed')]
        idle = {'method': 'thread/status/changed', 'params': {
            'threadId': 't', 'status': {'type': 'idle'}}}
        return [start, *hs, *items, idle]

    def test_compact_order_and_identity(self):
        inventory = self.inventory('preCompact')
        self.assertTrue(h.compact_complete(self.compact_rows(), 't', inventory))
        for mode in ('foreign_thread', 'foreign_turn', 'foreign_source', 'idle_early',
                     'item_mismatch', 'missing_start', 'missing_hook', 'failed_hook'):
            rows = self.compact_rows()
            if mode == 'foreign_thread':
                rows[1]['params']['threadId'] = rows[2]['params']['threadId'] = 'foreign'
            elif mode == 'foreign_turn':
                rows[1]['params']['turnId'] = rows[2]['params']['turnId'] = 'foreign'
            elif mode == 'foreign_source':
                for i in (1, 2):
                    rows[i]['params']['run']['sourcePath'] = '/other/hooks.json'
            elif mode == 'idle_early':
                rows.insert(3, rows.pop())
            elif mode == 'item_mismatch':
                rows[4]['params']['item']['id'] = 'other'
            elif mode == 'missing_start':
                rows.pop(3)
            elif mode == 'missing_hook':
                rows.pop(2)
            elif mode == 'failed_hook':
                rows[2]['params']['run']['status'] = 'failed'
            with self.subTest(mode=mode):
                try:
                    accepted = h.compact_complete(rows, 't', inventory)
                except ValueError:
                    accepted = False
                self.assertFalse(accepted)

    def inputs(self):
        state = {'mode': {'active': True}, 'requirements': [{'id': 'R001', 'status': 'pending'}],
                 'compactions': [], 'pending': {'recovery': None}}
        neg = {'decision_log': [{'outcome': 'visible_correction',
                                'reason_codes': ['waiting_condition_pending']}],
               'wait_conditions': [{'status': 'waiting'}]}
        cleanup = {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                   'process_group_cleanup_error': None}
        after = copy.deepcopy(state)
        after.update(compactions=[{'trigger': 'manual'}],
                     pending={'recovery': {'state': 'consumed'}})
        return [[{'status': 'completed'}] for _ in range(4)], [
            {'status': 'blocked'}, {'status': 'completed'}], state, after, neg, [
                cleanup, copy.deepcopy(cleanup)]

    def test_positive_and_macos_reaped_zombies(self):
        h.verdict(*self.inputs())

    def test_no_skips_empty_wrong_negative_recovery_or_cleanup(self):
        for mutation in ('positive', 'negative', 'inactive', 'lost', 'empty', 'reason',
                         'wait', 'cleanup', 'cleanup_error', 'cleanup_count', 'compact', 'consume'):
            with self.subTest(mutation=mutation):
                x = self.inputs()
                if mutation == 'positive':
                    x[0][0] = []
                elif mutation == 'negative':
                    x[1].pop(0)
                elif mutation == 'inactive':
                    x[2]['mode']['active'] = False
                elif mutation == 'lost':
                    x[3]['requirements'][0]['status'] = 'completed'
                elif mutation == 'empty':
                    x[2]['requirements'] = []
                elif mutation == 'reason':
                    x[4]['decision_log'][0]['reason_codes'] = []
                elif mutation == 'wait':
                    x[4]['wait_conditions'][0]['status'] = 'released'
                elif mutation == 'cleanup':
                    x[5][0]['owned_tree_no_running_members'] = False
                elif mutation == 'cleanup_error':
                    x[5][0]['process_group_cleanup_error'] = 'denied'
                elif mutation == 'compact':
                    x[3]['compactions'] = []
                elif mutation == 'consume':
                    x[3]['pending']['recovery']['state'] = 'ready'
                elif mutation == 'cleanup_count':
                    x[5].pop()
                with self.assertRaises(ValueError):
                    h.verdict(*x)


if __name__ == '__main__':
    unittest.main()
