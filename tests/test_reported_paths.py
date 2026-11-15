"""Reported paths are compared lexically, never queried as filesystem paths."""
import copy
import io
import json
import types
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from tests import test_native_between_turns_acceptance as orig

bt, u = orig.bt, orig.u
HOME = r'E:\Fixture\Home\.codex'
BASE = HOME + r'\plugins\cache\codex-context-guard\context-guard'
SOURCE = BASE + r'\0.18.0\hooks\hooks.json'
ARTIFACT = r'E:\Releases\Guard\artifact'
WORK = r'E:\Work\Repo'


class ReportedPaths(unittest.TestCase):
    def test_official_sources_cross_platform_without_path_io(self):
        ctx = {'cli': Path(r'E:\Tools\codex.exe')}
        good = {'installed': [{'pluginId': bt.ENTRY, 'version': '0.18.0', 'installed': True, 'enabled': True,
                              'marketplaceSource': {'sourceType': 'local', 'source': r'\\?\e:\releases\guard\artifact'},
                              'source': {'source': 'local', 'path': 'E:/RELEASES/GUARD/ARTIFACT'}}]}
        with (mock.patch.object(bt.platform, 'system', return_value='Windows'),
              mock.patch.object(bt, 'owned_read', return_value=json.dumps(good).encode()),
              mock.patch.object(Path, 'resolve', side_effect=AssertionError('reported path was resolved'))):
            self.assertTrue(bt.official_list(ctx, '0.18.0', Path(ARTIFACT))['target_source_verified'])
        for field in ('marketplaceSource', 'source'):
            for value in (r'E:\Releases\x\..\Guard\artifact', r'F:\Releases\Guard\artifact',
                          r'E:\Releases\Guard\artifact:stream', r'\\server\share\artifact',
                          'artifact', None, 42):
                bad = copy.deepcopy(good)
                bad['installed'][0][field]['source' if field == 'marketplaceSource' else 'path'] = value
                with (self.subTest(field=field, value=value), mock.patch.object(bt.platform, 'system', return_value='Windows'),
                      mock.patch.object(bt, 'owned_read', return_value=json.dumps(bad).encode()),
                      mock.patch.object(Path, 'resolve', side_effect=AssertionError('reported path was resolved')),
                      self.assertRaises(bt.Refused)):
                    bt.official_list(ctx, '0.18.0', Path(ARTIFACT))
        for field in ('marketplaceSource', 'source'):
            bad = copy.deepcopy(good)
            bad['installed'][0][field] = {'sourceType': 'remote'} if field == 'marketplaceSource' else {'source': 'remote'}
            with (mock.patch.object(bt.platform, 'system', return_value='Windows'),
                  mock.patch.object(bt, 'owned_read', return_value=json.dumps(bad).encode()),
                  self.assertRaises(bt.Refused)):
                bt.official_list(ctx, '0.18.0', Path(ARTIFACT))

    def test_approved_windows_spellings_and_rejected_ambiguities(self):
        with mock.patch.object(bt.platform, 'system', return_value='Windows'):
            for value in (ARTIFACT, ARTIFACT.lower(), 'E:/Releases/Guard/artifact', r'\\?\E:\Releases\Guard\artifact'):
                self.assertTrue(bt.reported_path_matches(value, Path(ARTIFACT)), value)
            for value in (r'E:\Releases\foo\..\Guard\artifact', r'E:\Releases\Guard\artifact.',
                          r'E:\Releases\Guard\artifact:stream', r'\\.\E:\Releases\Guard\artifact',
                          r'\\server\share\artifact', 'relative', None):
                self.assertFalse(bt.reported_path_matches(value, Path(ARTIFACT)), str(value))
            unc = r'\\server\share\artifact'
            self.assertTrue(bt.reported_path_matches(unc, Path(unc)))
            self.assertFalse(bt.reported_path_matches(r'\\SERVER\share\artifact', Path(unc)))
            self.assertFalse(bt.reported_path_matches(r'\\?\UNC\server\share\artifact', Path(unc)))
        with (mock.patch.object(bt.platform, 'system', return_value='Darwin'),
              mock.patch.object(bt, 'Path', PurePosixPath)):
            self.assertTrue(bt.reported_path_matches('/tmp/artifact', '/tmp/artifact'))
            self.assertFalse(bt.reported_path_matches('/tmp/other/../artifact', '/tmp/artifact'))

    def test_hook_inventory_matches_extended_and_rejects_unsafe_ccg_sources(self):
        rows = orig.inv(SOURCE)
        for row in rows['data'][0]['hooks']:
            row['sourcePath'] = r'\\?\e:' + SOURCE[2:].lower()
        rows['data'][0]['hooks'] += [
            {'sourcePath': HOME + r'\plugins\cache\other\item\hooks\hooks.json'},
            {'sourcePath': BASE + r'-other\item\hooks\hooks.json'},
        ]
        with mock.patch.object(bt.platform, 'system', return_value='Windows'):
            self.assertEqual(len(bt.product_inventory(u, rows, Path(BASE), [Path(SOURCE)])), 9)
            for bad in (BASE + r'\0.99.0\hooks\hooks.json', BASE + r'\0.18.0\..\0.18.0\hooks\hooks.json',
                        BASE + r'\0.18.0\hooks\hooks.json:secret', '\\\\.\\' + SOURCE,
                        BASE + r'. \0.18.0\hooks\hooks.json',
                        HOME + r'\plugins\cache\codex-context-guard. \context-guard\0.18.0\hooks\hooks.json',
                        HOME + r'\plugins\cache\codex-context-guard:ads\context-guard\0.18.0\hooks\hooks.json',
                        r'plugins\cache\codex-context-guard\context-guard\x\hooks.json'):
                mixed = copy.deepcopy(rows)
                mixed['data'][0]['hooks'].append({'sourcePath': bad})
                with self.subTest(source=bad), self.assertRaises(bt.Refused):
                    bt.product_inventory(u, mixed, Path(BASE), [Path(SOURCE)])

    def test_hook_receive_uses_same_scope_router(self):
        expected = {'eventName': 'userPromptSubmit', 'source': 'plugin', 'handlerType': 'command',
                    'displayOrder': 0, 'async': False}
        class Base:
            def rpc(self, method, params):
                return {'config': {'model_provider': None, 'model_providers': {}, 'windows': {'sandbox': 'mxc'}}} if method == 'config/read' else {}
            def send(self, message):
                pass
            def journal_response(self, message):
                return message
        class Owned:
            process = types.SimpleNamespace(pid=42, stdin=io.StringIO(), stdout=io.StringIO())
            def close(self, timeout):
                return {'cleanup_complete': True, 'owned_process_exited': True, 'owned_tree_no_running_members': True,
                        'process_group_cleanup_error': None, 'job_close_confirmed': True, 'job_assignment_confirmed': True}
        tree = types.SimpleNamespace(spawn=lambda *a, **k: Owned())
        fake_u = types.SimpleNamespace(UpgradeClient=Base, _source_key=u._source_key)
        with (self.subTest('receive'), mock.patch.object(bt.platform, 'system', return_value='Windows'),
              mock.patch.object(bt, 'product_inventory', return_value={('userPromptSubmit', SOURCE): expected})):
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                ctx = {'u': fake_u, 'host': types.SimpleNamespace(OwnedProcess=tree, Client=Base),
                       'output': Path(tmp), 'old_root': Path(BASE), 'new_root': Path(BASE), 'home': Path(HOME),
                       'cli': Path(r'E:\Tools\codex.exe'), 'workspace': Path(WORK), 'read_file': Path('README.md'),
                       'expected_model': 'model', 'app_server_argv': ['fixture'], 'windows_backend': 'mxc'}
                client = bt.DailyClientFactory(ctx)()
                try:
                    client._projection = lambda m: None
                    def event(src):
                        return {'method': 'hook/started', 'params': {'run': {**expected, 'sourcePath': src, 'executionMode': 'sync'}}}
                    client.q.put(event(r'\\?\e:' + SOURCE[2:].lower()))
                    self.assertEqual(client.receive(10000000000)['method'], 'hook/started')
                    client.q.put(event(HOME + r'\plugins\cache\other\x\hooks.json'))
                    self.assertEqual(client.receive(10000000000)['method'], 'hook/started')
                    client.q.put(event(BASE + r'\0.18.0\..\0.18.0\hooks\hooks.json'))
                    with self.assertRaises(bt.Refused):
                        client.receive(10000000000)
                    client.q.put(event(BASE + r'. \0.18.0\hooks\hooks.json'))
                    with self.assertRaises(bt.Refused):
                        client.receive(10000000000)
                finally:
                    client.close()

    def test_hook_inventory_accepts_two_bound_sources_only(self):
        older = BASE + r'\0.17.3\hooks\hooks.json'
        rows = orig.inv(older)
        rows['data'][0]['hooks'].extend(orig.inv(SOURCE)['data'][0]['hooks'])
        for row in rows['data'][0]['hooks']:
            row['sourcePath'] = r'\\?\e:' + row['sourcePath'][2:].lower()
        with mock.patch.object(bt.platform, 'system', return_value='Windows'):
            self.assertEqual(len(bt.product_inventory(u, rows, Path(BASE), [Path(older), Path(SOURCE)])), 18)
            rows['data'][0]['hooks'].append({'sourcePath': BASE + r'\0.16.0\hooks\hooks.json'})
            with self.assertRaises(bt.Refused):
                bt.product_inventory(u, rows, Path(BASE), [Path(older), Path(SOURCE)])

    def test_hook_pairs_accept_extended_source_and_reject_drift(self):
        inventory = {('userPromptSubmit', SOURCE): {'eventName': 'userPromptSubmit', 'source': 'plugin',
                    'handlerType': 'command', 'displayOrder': 0, 'async': False}}
        run = {'id': 'R', 'eventName': 'userPromptSubmit', 'sourcePath': r'\\?\e:' + SOURCE[2:].lower(),
               'source': 'plugin', 'handlerType': 'command', 'displayOrder': 0, 'executionMode': 'sync'}
        def event(method, value):
            return {'direction': 'response', 'message': {'method': method,
                    'params': {'threadId': 'T', 'turnId': 'U', 'run': value}}}
        rows = [event('hook/started', run), event('hook/completed', {**run, 'status': 'completed', 'durationMs': 1})]
        with mock.patch.object(bt.platform, 'system', return_value='Windows'):
            self.assertEqual(len(u._paired(rows, inventory, 'T', 'userPromptSubmit', turn='U')), 1)
            altered = copy.deepcopy(rows)
            altered[1]['message']['params']['run']['sourcePath'] = BASE + r'\0.18.0\..\0.18.0\hooks\hooks.json'
            with self.assertRaises(Exception):
                u._paired(altered, inventory, 'T', 'userPromptSubmit', turn='U')

    def test_maintained_market_and_cache_receipts_reject_dot_aliases(self):
        fixture = orig.Tests()
        fixture.setUp()
        try:
            fixture.write_receipts()
            out = fixture.ctx['tool_output']
            with mock.patch.object(bt.platform, 'system', return_value='Darwin'):
                self.assertEqual(bt.verify_maintained(fixture.ctx, fixture.plan, out / 'verify.json', 'passed')['journal_add_count'], 1)
                for filename, field, trusted in (('apply.json', 'market_root', fixture.artifact),
                                                 ('apply.json', 'cache_path', fixture.new),
                                                 ('verify.json', 'cache_path', fixture.new)):
                    path = out / filename
                    original = path.read_bytes()
                    changed = json.loads(original)
                    changed['installed_after'][field] = str(trusted.parent / 'other' / '..' / trusted.name)
                    path.write_text(json.dumps(changed))
                    with self.subTest(filename=filename, field=field), self.assertRaises(bt.Refused):
                        bt.verify_maintained(fixture.ctx, fixture.plan, out / 'verify.json', 'passed')
                    path.write_bytes(original)
        finally:
            fixture.tearDown()

    def test_maintained_receipt_windows_aliases_are_bound_lexically(self):
        fixture = orig.Tests()
        fixture.setUp()
        try:
            fixture.write_receipts()
            out = fixture.ctx['tool_output']
            apply_path, verify_path = out / 'apply.json', out / 'verify.json'
            applied, verified = json.loads(apply_path.read_text()), json.loads(verify_path.read_text())
            cache_expected = BASE + r'\0.18.0'
            applied['installed_after']['market_root'] = r'\\?\e:\releases\guard\artifact'
            applied['installed_after']['cache_path'] = r'\\?\e:' + cache_expected[2:].lower()
            verified['installed_after']['cache_path'] = r'\\?\e:' + cache_expected[2:].lower()
            apply_path.write_text(json.dumps(applied))
            verify_path.write_text(json.dumps(verified))
            matcher = bt.reported_path_matches
            def map_trusted(raw, trusted):
                expected = ARTIFACT if trusted == fixture.artifact else cache_expected if trusted == fixture.new else str(trusted)
                return matcher(raw, Path(expected))
            with (mock.patch.object(bt.platform, 'system', return_value='Windows'),
                  mock.patch.object(bt, 'reported_path_matches', side_effect=map_trusted)):
                self.assertEqual(bt.verify_maintained(fixture.ctx, fixture.plan, verify_path, 'passed')['journal_add_count'], 1)
                for filename, field in (('apply.json', 'market_root'), ('apply.json', 'cache_path'), ('verify.json', 'cache_path')):
                    path = out / filename
                    saved = path.read_bytes()
                    altered = json.loads(saved)
                    altered['installed_after'][field] += r'\..\other'
                    path.write_text(json.dumps(altered))
                    with self.subTest(filename=filename, field=field), self.assertRaises(bt.Refused):
                        bt.verify_maintained(fixture.ctx, fixture.plan, verify_path, 'passed')
                    path.write_bytes(saved)
        finally:
            fixture.tearDown()

    def test_verify_read_tool_uses_windows_cwd_without_resolve(self):
        def event(method, run=None, item=None):
            return {'direction': 'response', 'message': {'method': method,
                    'params': {'threadId': 'T', 'turnId': 'R', 'run': run or {}, 'item': item or {}}}}
        item = {'id': 'I', 'type': 'commandExecution', 'command': 'read', 'cwd': r'\\?\e:\work\repo'}
        rows = [event('hook/completed', run={'eventName': 'preToolUse'}), event('item/started', item=item),
                event('item/completed', item={**item, 'exitCode': 0}), event('hook/started', run={'eventName': 'postToolUse'})]
        ctx = {'workspace': Path(WORK), 'u': types.SimpleNamespace(_paired=lambda *a, **k: [{}])}
        with (mock.patch.object(bt.platform, 'system', return_value='Windows'),
              mock.patch.object(Path, 'resolve', side_effect=AssertionError('reported cwd was resolved'))):
            bt.verify_read_tool(ctx, rows, {}, 'T', 'R', 'read')
            rows[1]['message']['params']['item']['cwd'] = r'E:\Work\x\..\Repo'
            with self.assertRaises(bt.Refused):
                bt.verify_read_tool(ctx, rows, {}, 'T', 'R', 'read')


if __name__ == '__main__':
    unittest.main()
