"""Synthetic CLI mutations exercise the namespace transaction, not native trust."""
import copy
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock

from tools.validation import candidate_namespace as candidate


class FakeCLI:
    def __init__(self, binary, home):
        self.home = home
        self.namespace = None
        self.wrapper = None
        self.failure = None
        self.calls = []

    def call(self, *args, **kwargs):
        self.calls.append(args)
        if args == ('login', 'status'):
            return 'Not logged in' if self.failure != 'authenticated' else 'Logged in using ChatGPT'
        if args[:3] == ('plugin', 'marketplace', 'list'):
            return {'marketplaces': [] if self.namespace is None else [{
                'name': self.namespace, 'root': str(self.wrapper)}]}
        if args[:3] == ('plugin', 'marketplace', 'add'):
            self.wrapper = Path(args[3])
            self.namespace = json.loads((self.wrapper / '.agents/plugins/marketplace.json').read_text())['name']
            with (self.home / 'config.toml').open('ab') as stream:
                stream.write((f'\n[marketplaces.{self.namespace}]\nsource_type = "local"\n'
                              f'source = {json.dumps(str(self.wrapper))}\n').encode())
            if self.failure == 'registration':
                raise candidate.Rejected('synthetic_registration_failure')
            return {'name': self.namespace}
        if args[:2] == ('plugin', 'add'):
            product = self.wrapper / 'product'
            version = candidate.manager.source_plugin_version(product)
            installed = self.home / 'plugins/cache' / self.namespace / 'context-guard' / version
            shutil.copytree(product, installed)
            with (self.home / 'config.toml').open('ab') as stream:
                stream.write(f'\n[plugins."context-guard@{self.namespace}"]\nenabled = true\n'.encode())
            if self.failure == 'partial_cache':
                raise candidate.Rejected('synthetic_install_failure')
            return {'pluginId': 'context-guard@' + self.namespace, 'name': 'context-guard',
                    'marketplaceName': self.namespace, 'version': version,
                    'installedPath': str(installed) if self.failure != 'path' else '/wrong/cache'}
        raise AssertionError(args)


@unittest.skipIf(candidate.tomllib is None, 'namespace acceptance tool requires Python 3.11 TOML parser')
class NamespaceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root, self.home = self.base / 'repo', self.base / 'home'
        (self.root / '.codex-plugin').mkdir(parents=True)
        (self.root / '.codex-plugin/plugin.json').write_text(json.dumps({'name': 'context-guard', 'version': '0.14.2'}))
        (self.root / 'README.md').write_text('Synthetic public product\n')
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Fixture', '-c',
                        'user.email=fixture@users.noreply.github.com', 'commit', '-qm', 'Synthetic fixture'], check=True)
        self.home.mkdir()
        (self.home / 'config.toml').write_bytes(b'# Exact original configuration\n')
        self.old = self.home / 'plugins/cache/codex-context-guard/context-guard/0.14.2/old.py'
        self.old.parent.mkdir(parents=True)
        self.old.write_bytes(b'consumed immutable bytes\n')
        self.before_old = candidate.old_cache_snapshot(self.home, 'cg-candidate-unit')
        self.before_config = candidate.config_snapshot(self.home / 'config.toml')
        self.binary = self.base / 'fixture-binary'
        self.binary.write_bytes(b'never executed: synthetic official CLI boundary')
        files = {p: candidate.digest((self.root / p).read_bytes()) for p in ('.codex-plugin/plugin.json', 'README.md')}
        self.source_pin = candidate.digest(candidate.canonical(files))
        self.runtime_pin = candidate.digest(candidate.canonical(candidate.manager.tree_manifest(self.root)))
        self.manifest = self.base / 'identity.json'
        self.identity = {'files': files, 'source_tree_sha256': self.source_pin,
                         'runtime_tree_sha256': self.runtime_pin,
                         'base_commit': subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD']).decode().strip()}
        self.manifest.write_text(json.dumps(self.identity))
        self.cli = FakeCLI(self.binary, self.home)
        self.args = dict(root=self.root, home=self.home, transaction=self.base / 'transaction',
                         manifest=self.manifest, source_pin=self.source_pin, runtime_pin=self.runtime_pin,
                         namespace='cg-candidate-unit', binary=self.binary,
                         binary_pin=candidate.digest(self.binary.read_bytes()), cli_factory=lambda *_: self.cli)

    def unchanged(self):
        self.assertEqual(candidate.config_snapshot(self.home / 'config.toml'), self.before_config)
        self.assertEqual(candidate.old_cache_snapshot(self.home, 'cg-candidate-unit'), self.before_old)

    def test_install_archive_exact_restore_and_strict_noop(self):
        result = candidate.install(**self.args, apply=True)
        self.assertEqual(result['status'], 'installed')
        self.unchanged()
        before = copy.deepcopy(self.cli.calls)
        self.assertEqual(candidate.install(**self.args, apply=True)['status'], 'strict_noop')
        self.assertEqual(self.cli.calls, before)
        self.assertFalse(result['automatic_cleanup'])
        self.assertEqual(result['native_acceptance'], 'not_established')
        # Codex -c splits key paths on dots; TOML quotes become literal key bytes.
        self.assertTrue(result['activation_overrides']['plugins.context-guard@cg-candidate-unit.enabled'])

    def test_missing_home_and_noop_during_writer_are_rejected(self):
        with self.assertRaisesRegex(candidate.Rejected, 'existing_isolated_home'):
            candidate.install(**{**self.args, 'home': self.base / 'absent'}, apply=True)
        candidate.install(**self.args, apply=True)
        (self.home / '.candidate-namespace-transaction.lock').mkdir()
        with self.assertRaisesRegex(candidate.Rejected, 'concurrent_namespace_writer'):
            candidate.install(**self.args, apply=True)

    def test_preflight_does_not_create_target_or_transaction(self):
        self.assertEqual(candidate.install(**self.args)['status'], 'inputs_ready')
        self.assertFalse(self.args['transaction'].exists())
        self.unchanged()

    def test_wrong_base_or_payload_rejected_before_cli(self):
        self.identity['base_commit'] = '0' * 40
        self.manifest.write_text(json.dumps(self.identity))
        with self.assertRaisesRegex(candidate.Rejected, 'base_commit'):
            candidate.install(**self.args, apply=True)
        self.assertEqual(self.cli.calls, [])
        self.identity['base_commit'] = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD']).decode().strip()
        self.manifest.write_text(json.dumps(self.identity))
        (self.root / 'README.md').write_text('Changed source')
        with self.assertRaisesRegex(candidate.Rejected, 'source_file_mismatch'):
            candidate.install(**self.args, apply=True)
        self.assertEqual(self.cli.calls, [])

    def test_authenticated_home_is_not_in_this_contract(self):
        self.cli.failure = 'authenticated'
        with self.assertRaisesRegex(candidate.Rejected, 'unauthenticated'):
            candidate.install(**self.args, apply=True)
        self.unchanged()

    def scope_record(self):
        subject = candidate.install(**self.args)['subject']
        path = self.base / 'operator-scope.json'
        value = {'schema': 'candidate-home-scope/v1', 'purpose': 'existing_private_acceptance_home',
                 'subject': subject, 'not_before': time.time() - 1, 'expires_at': time.time() + 60}
        path.write_text(json.dumps(value))
        self.cli.failure = 'authenticated'
        return path, value

    def test_explicit_bound_authenticated_target_install_and_noop(self):
        path, _ = self.scope_record()
        observations = []
        args = {**self.args, 'authorization': path, 'authorization_pin': candidate.digest(path.read_bytes()),
                'idle_checker': lambda home: observations.append(home)}
        self.assertEqual(candidate.install(**args, apply=True)['status'], 'installed')
        self.assertEqual(observations, [self.home] * 3)
        self.assertEqual(candidate.install(**args, apply=True)['status'], 'strict_noop')
        self.unchanged()

    def test_scope_record_rejects_target_pin_expiry_and_daily_home(self):
        path, value = self.scope_record()
        args = {**self.args, 'authorization': path, 'authorization_pin': candidate.digest(path.read_bytes())}
        for field, changed in (('home', '/different/home'), ('source_tree_sha256', '0' * 64),
                               ('runtime_tree_sha256', '0' * 64), ('binary_sha256', '0' * 64),
                               ('installer_sha256', '0' * 64), ('namespace', 'cg-candidate-other')):
            modified = copy.deepcopy(value)
            modified['subject'][field] = changed
            path.write_text(json.dumps(modified))
            with self.subTest(field=field), self.assertRaisesRegex(candidate.Rejected, 'authorization_target'):
                candidate.install(**{**args, 'authorization_pin': candidate.digest(path.read_bytes())}, apply=True)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(candidate.Rejected, 'authorization_pin'):
            candidate.install(**{**args, 'authorization_pin': '0' * 64}, apply=True)
        value['not_before'] = time.time() - 90
        value['expires_at'] = time.time() - 30
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(candidate.Rejected, 'expired'):
            candidate.install(**{**args, 'authorization_pin': candidate.digest(path.read_bytes())}, apply=True)
        with self.assertRaisesRegex(candidate.Rejected, 'explicit_private'):
            candidate.authorized_home(path, candidate.digest(path.read_bytes()), value['subject'],
                                      Path.home() / '.codex')
        self.assertFalse(self.args['transaction'].exists())
        self.unchanged()

    def test_active_authenticated_home_is_not_disturbed(self):
        path, _ = self.scope_record()
        def occupied(home):
            raise candidate.Rejected('target_home_has_active_process')
        with self.assertRaisesRegex(candidate.Rejected, 'active_process'):
            candidate.install(**self.args, authorization=path,
                              authorization_pin=candidate.digest(path.read_bytes()),
                              idle_checker=occupied, apply=True)
        self.assertFalse(self.args['transaction'].exists())
        self.unchanged()

    def test_windows_idle_observation_covers_each_file_and_directory_without_content_read(self):
        child = self.home / 'nested'
        child.mkdir()
        (child / 'sample.txt').write_text('synthetic')
        observed = []
        with mock.patch.object(candidate, '_win32_open_exclusive',
                               side_effect=lambda path, is_dir, api: observed.append((path, is_dir))):
            candidate._require_windows_home_without_conflicting_handles(self.home, api=object())
        self.assertIn((self.home, True), observed)
        self.assertIn((child, True), observed)
        self.assertIn((child / 'sample.txt', False), observed)
        with mock.patch.object(candidate, '_win32_open_exclusive',
                               side_effect=candidate.Rejected('target_home_has_active_process')):
            with self.assertRaisesRegex(candidate.Rejected, 'active_process'):
                candidate._require_windows_home_without_conflicting_handles(self.home,
                                                                             api=object())

    def test_windows_exclusive_open_closes_every_created_handle_and_classifies_errors(self):
        class FakeApi:
            invalid_handle = -1
            handle = 17
            error = 0
            attributes_value = 0x10
            attributes_error = False
            close_ok = True

            def __init__(self):
                self.calls = []

            def create(self, *args):
                self.calls.append(('create', args))
                return self.handle

            def last_error(self):
                return self.error

            def attributes(self, handle):
                self.calls.append(('attributes', handle))
                if self.attributes_error:
                    raise candidate.Rejected('home_activity_observation_unknown')
                return self.attributes_value

            def close(self, handle):
                self.calls.append(('close', handle))
                return self.close_ok

        api = FakeApi()
        candidate._win32_open_exclusive(self.home, True, api)
        self.assertEqual(api.calls[0][1][1:6], (1, 0, None, 3, 0x02200000))
        self.assertEqual([call[0] for call in api.calls], ['create', 'attributes', 'close'])
        for error, reason in ((32, 'active_process'), (5, 'observation_unknown')):
            api = FakeApi()
            api.handle, api.error = -1, error
            with self.subTest(error=error), self.assertRaisesRegex(candidate.Rejected, reason):
                candidate._win32_open_exclusive(self.home, True, api)
            self.assertEqual([call[0] for call in api.calls], ['create'])
        for field, value in (('attributes_error', True), ('attributes_value', 0x410),
                             ('close_ok', False)):
            api = FakeApi()
            setattr(api, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(candidate.Rejected,
                                                                    'observation_unknown'):
                candidate._win32_open_exclusive(self.home, True, api)
            self.assertEqual([call[0] for call in api.calls], ['create', 'attributes', 'close'])
        # A metadata-only directory handle can coexist with our exclusive open.
        # This successful observation does not certify global HOME idleness.
        api = FakeApi()
        candidate._win32_open_exclusive(self.home, True, api)

    def test_windows_tree_limit_stops_consuming_a_lazy_directory(self):
        consumed = []
        class Listing:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def __iter__(self):
                for index in range(100):
                    consumed.append(index)
                    yield type('Entry', (), {'path': str(self_home / str(index))})()

        self_home = self.home
        with mock.patch.object(candidate.os, 'scandir', return_value=Listing()):
            with self.assertRaisesRegex(candidate.Rejected, 'observation_unknown'):
                candidate._windows_home_entries(self.home, deadline=time.monotonic() + 5,
                                                max_entries=2)
        self.assertEqual(len(consumed), 2)

    def test_windows_idle_observation_fails_closed_on_links_limits_and_changed_type(self):
        with self.assertRaisesRegex(candidate.Rejected, 'observation_unknown'):
            candidate._windows_home_entries(self.home, deadline=time.monotonic() - 1)
        with self.assertRaisesRegex(candidate.Rejected, 'observation_unknown'):
            candidate._windows_home_entries(self.home, deadline=time.monotonic() + 5,
                                            max_entries=1)
        for attributes, is_dir in ((0x400, False), (0x410, True),
                                   (0x10, False), (0, True)):
            with self.subTest(attributes=attributes, is_dir=is_dir):
                with self.assertRaisesRegex(candidate.Rejected, 'observation_unknown'):
                    candidate._verify_opened_windows_attributes(attributes, is_dir)
        link = self.home / 'linked'
        try:
            link.symlink_to(self.old, target_is_directory=False)
        except OSError:
            self.skipTest('host cannot create fixture symlink')
        with self.assertRaisesRegex(candidate.Rejected, 'observation_unknown|linked_path'):
            candidate._windows_home_entries(self.home, deadline=time.monotonic() + 5)

    def test_handled_partial_failure_retains_unattributed_config_and_cache(self):
        self.cli.failure = 'partial_cache'
        with self.assertRaises(candidate.Rejected):
            candidate.install(**self.args, apply=True)
        self.assertIn(b'enabled = true', (self.home / 'config.toml').read_bytes())
        target = self.home / 'plugins/cache/cg-candidate-unit/context-guard/0.14.2'
        self.assertTrue(target.is_dir())
        self.assertFalse((self.args['transaction'] / 'receipt.json').exists())
        with self.assertRaisesRegex(candidate.Rejected, 'existing_or_incomplete'):
            candidate.install(**self.args, apply=True)

    def test_registration_failure_preserves_unattributed_partial_write(self):
        self.cli.failure = 'registration'
        with self.assertRaises(candidate.Rejected):
            candidate.install(**self.args, apply=True)
        self.assertIn(b'source_type', (self.home / 'config.toml').read_bytes())

    def test_unrelated_success_and_exception_edits_are_not_overwritten(self):
        original = self.cli.call
        for edit in (b'\nuser_added_setting = true\n', b'\n# unrelated comment\n'):
            with self.subTest(edit=edit):
                # Pure audit rejects both new settings and unrelated comments.
                raw = self.before_config[0] + edit
                with self.assertRaisesRegex(candidate.Rejected, 'unattributed'):
                    candidate.namespace_config_delta(self.before_config, (raw, 0o600, 0),
                                                     'cg-candidate-unit', self.base)
        def concurrent(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[:2] == ('plugin', 'add'):
                with (self.home / 'config.toml').open('ab') as stream:
                    stream.write(b'\nuser_added_setting = true\n')
            return result
        self.cli.call = concurrent
        with self.assertRaisesRegex(candidate.Rejected, 'concurrent_config_change'):
            candidate.install(**self.args, apply=True)
        self.assertIn(b'user_added_setting', (self.home / 'config.toml').read_bytes())
        self.assertFalse((self.args['transaction'] / 'receipt.json').exists())

    def test_existing_value_change_during_failing_cli_is_preserved(self):
        self.assert_concurrent_value_preserved(fail=True, new_key=False)

    def test_existing_value_change_during_successful_cli_is_preserved(self):
        self.assert_concurrent_value_preserved(fail=False, new_key=False)

    def test_new_key_during_failing_cli_is_preserved(self):
        self.assert_concurrent_value_preserved(fail=True, new_key=True)

    def assert_concurrent_value_preserved(self, *, fail, new_key):
        path = self.home / 'config.toml'
        path.write_bytes(b'old_setting = false\n')
        original = self.cli.call
        def concurrent(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[:2] == ('plugin', 'add'):
                raw = path.read_bytes()
                path.write_bytes(raw + b'new_setting = true\n' if new_key else
                                 raw.replace(b'old_setting = false', b'old_setting = true'))
                if fail:
                    raise candidate.Rejected('failed_after_unrelated_edit')
            return result
        self.cli.call = concurrent
        with self.assertRaisesRegex(candidate.Rejected, 'concurrent_config_change'):
            candidate.install(**self.args, apply=True)
        self.assertIn(b'new_setting = true' if new_key else b'old_setting = true', path.read_bytes())
        self.assertEqual(json.loads((self.args['transaction'] / 'incomplete.json').read_bytes())['status'],
                         'incomplete')

    def test_official_returned_path_must_match_namespace(self):
        self.cli.failure = 'path'
        with self.assertRaisesRegex(candidate.Rejected, 'installed_path_or_identity'):
            candidate.install(**self.args, apply=True)
        self.unchanged()

    def test_second_transaction_cannot_adopt_existing_namespace(self):
        candidate.install(**self.args, apply=True)
        with self.assertRaisesRegex(candidate.Rejected, 'existing_or_incomplete'):
            candidate.install(**{**self.args, 'transaction': self.base / 'other'}, apply=True)
        self.unchanged()

    def test_changed_consumed_cache_is_not_repaired(self):
        candidate.install(**self.args, apply=True)
        file = self.home / 'plugins/cache/cg-candidate-unit/context-guard/0.14.2/README.md'
        file.write_text('tampered')
        with self.assertRaisesRegex(candidate.Rejected, 'consumed_cache_changed'):
            candidate.install(**self.args, apply=True)
        self.assertEqual(file.read_text(), 'tampered')

    def test_path_traversal_symlink_and_existing_targets(self):
        for namespace in ('../other', 'codex-context-guard', 'cg-candidate-a/b'):
            with self.assertRaises(candidate.Rejected):
                candidate.install(**{**self.args, 'namespace': namespace}, apply=True)
        link = self.base / 'link'
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest('host cannot create fixture symlink')
        with self.assertRaisesRegex(candidate.Rejected, 'linked_path'):
            candidate.install(**{**self.args, 'root': link}, apply=True)

    def test_concurrent_writer_is_rejected_without_removing_its_lock(self):
        lock = self.home / '.candidate-namespace-transaction.lock'
        lock.mkdir()
        with self.assertRaisesRegex(candidate.Rejected, 'concurrent_namespace_writer'):
            candidate.install(**self.args, apply=True)
        self.assertTrue(lock.exists())
        self.unchanged()

    def test_restore_refuses_later_unrelated_config_write(self):
        path = self.home / 'config.toml'
        path.write_bytes(b'new unrelated configuration')
        with self.assertRaisesRegex(candidate.Rejected, 'concurrent_config_change'):
            candidate.restore_config(path, self.before_config, self.before_config)
        self.assertEqual(path.read_bytes(), b'new unrelated configuration')

    def test_multiline_values_and_hidden_sections_cannot_be_normalized(self):
        section = '[marketplaces.cg-candidate-unit]\nsource_type = "local"\nsource = "/fixture"\n'
        for quote in ('"""', "'''"):
            old = f'custom = {quote}line1\n\nline2{quote}\n'.encode()
            after = old.replace(b'line1\n\nline2', b'line1\nline2') + section.encode()
            with self.subTest(quote=quote), self.assertRaises(candidate.Rejected):
                candidate.namespace_config_delta((old, 0o600, 0), (after, 0o600, 1),
                                                 'cg-candidate-unit', Path('/fixture'))
            after = old.replace(b'line2', section.encode() + b'line2')
            with self.assertRaises(candidate.Rejected):
                candidate.namespace_config_delta((old, 0o600, 0), (after, 0o600, 1),
                                                 'cg-candidate-unit', Path('/fixture'))
        old = b'# unrelated comment\n'
        for after in (b'# unrelated comment changed\n' + section.encode(),
                      b'# ' + section.encode() + old):
            with self.assertRaises(candidate.Rejected):
                candidate.namespace_config_delta((old, 0o600, 0), (after, 0o600, 1),
                                                 'cg-candidate-unit', Path('/fixture'))

    def test_windows_official_literal_extended_source_is_exact_delta(self):
        namespace = 'cg-candidate-c1c2-win-r17'
        wrapper = PureWindowsPath(r'C:\cg-fixture\marketplace')
        before = b'[features]\nfixture = true\n'
        section = (f'\n[marketplaces.{namespace}]\nsource_type = "local"\n'
                   "source = '\\\\?\\C:\\cg-fixture\\marketplace'\n").encode()
        accepted = candidate.namespace_config_delta(
            (before, 0o600, 0), (before + section, 0o600, 1), namespace, wrapper)
        self.assertEqual(accepted[0], before + section)
        for source in (r'\\?\C:\cg-fixture\other',
                       r'\\?\C:\cg-fixture\..\marketplace',
                       r'\\?\UNC\server\share\marketplace',
                       r'\\?\c:\cg-fixture\marketplace'):
            with self.subTest(source=source), self.assertRaises(candidate.Rejected):
                changed = (f'\n[marketplaces.{namespace}]\nsource_type = "local"\n'
                           f"source = '{source}'\n").encode()
                candidate.namespace_config_delta(
                    (before, 0o600, 0), (before + changed, 0o600, 1), namespace, wrapper)

    def test_failure_receipt_reports_stage_without_config_or_cli_text(self):
        self.cli.failure = 'registration'
        with self.assertRaises(candidate.Rejected):
            candidate.install(**self.args, apply=True)
        record = json.loads((self.args['transaction'] / 'failure.json').read_bytes())
        self.assertEqual(record['stage'], 'config_restore')
        self.assertEqual(record['prior_stage'], 'marketplace_add')
        self.assertEqual(record['reason'], 'concurrent_config_change_not_overwritten')
        self.assertNotIn('synthetic_registration_failure', json.dumps(record))
        self.assertFalse(record['automatic_retry'])
