"""Restricted zero-model candidate install into a new marketplace namespace.

Unauthenticated homes are the default; an existing private acceptance HOME
requires an explicit target-bound operator scope record. Official
CLI mutations install the cache; this tool only stages a frozen public source.
It reuses manage_plugin parity, archive and locking rules. Config is restored
only after an attributable namespace-only delta; unknown changes are retained.
Abrupt process death leaves an incomplete
transaction requiring inspection, never an automatic cleanup/retry. The caller
must own the HOME exclusively for the transaction (not an OS security boundary).
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import ntpath
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ImportError:  # Python 3.10 may run the product, but not this acceptance tool.
    tomllib = None

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('candidate_safe_manager', ROOT / 'scripts/manage_plugin.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class Rejected(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def safe_path(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise Rejected('absolute_confined_path_required')
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise Rejected('linked_path')
    return path


def read(path):
    path = safe_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 32 * 1024 * 1024:
        raise Rejected('unsafe_file')
    raw = path.read_bytes()
    after = path.stat()
    if any(getattr(after, key) != getattr(before, key) for key in (
            'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise Rejected('file_changed')
    return raw


def executable_digest(path):
    path = safe_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 * 1024:
        raise Rejected('unsafe_executable')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    after = path.stat()
    if any(getattr(after, key) != getattr(before, key) for key in (
            'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise Rejected('executable_changed')
    return value.hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Rejected('duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def write_new(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
    with Path(path).open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


class CLI:
    def __init__(self, binary, home):
        self.binary, self.home = binary, home

    def call(self, *args, json_result=True, allowed=(0,)):
        result = subprocess.run([str(self.binary), *args], env={**os.environ, 'CODEX_HOME': str(self.home)},
                                capture_output=True, timeout=30, check=False)
        if result.returncode not in allowed or len(result.stdout) + len(result.stderr) > 2 * 1024 * 1024:
            raise Rejected('official_cli_failed')
        return decode(result.stdout) if json_result else (result.stdout + result.stderr).decode('utf-8')


def source_manifest(root, path, source_pin, runtime_pin):
    value = decode(read(path))
    files = value.get('files')
    if (not isinstance(files, dict) or not 1 <= len(files) <= 1024
            or digest(canonical(files)) != source_pin
            or value.get('source_tree_sha256') != source_pin
            or value.get('runtime_tree_sha256') != runtime_pin):
        raise Rejected('source_pin_mismatch')
    base = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, check=True).stdout.decode().strip()
    if base != value.get('base_commit'):
        raise Rejected('base_commit_mismatch')
    for name, expected in files.items():
        relative = PurePosixPath(name)
        if (not name or relative.is_absolute() or str(relative) != name or '..' in relative.parts
                or '\\' in name or ':' in name or any(part in manager.IGNORED_TREE_NAMES for part in relative.parts)
                or not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected)):
            raise Rejected('unsafe_source_member')
        if digest(read(root / name)) != expected:
            raise Rejected('source_file_mismatch')
    actual = digest(canonical(manager.tree_manifest(root)))
    if actual != runtime_pin:
        raise Rejected('runtime_pin_mismatch')
    return files, manager.source_plugin_version(root)


def old_cache_snapshot(home, namespace):
    result = {}
    for directory in ('cache', 'cache-archive'):
        root = safe_path(home / 'plugins' / directory)
        if not root.exists():
            continue
        for entry in root.iterdir():
            safe_path(entry)
            if entry.name == namespace:
                continue
            for path in entry.rglob('*'):
                safe_path(path)
                if path.is_file():
                    result[str(path.relative_to(home))] = [digest(read(path)), path.stat().st_mtime_ns]
    return result


def config_snapshot(path):
    if not path.exists():
        return None
    raw = read(path)
    return raw, stat.S_IMODE(path.stat().st_mode), path.stat().st_mtime_ns


def restore_config(path, before, expected):
    if config_snapshot(path) != expected:
        raise Rejected('concurrent_config_change_not_overwritten')
    if before is None:
        if path.exists():
            path.unlink()
    elif config_snapshot(path) != before:
        temporary = path.with_name('.config.candidate-restore')
        with temporary.open('xb') as stream:
            os.chmod(temporary, before[1])
            stream.write(before[0])
        temporary.replace(path)
        os.utime(path, ns=(before[2], before[2]))
    if config_snapshot(path) != before:
        raise Rejected('config_restore_failed')


def namespace_config_delta(before, after, namespace, wrapper, *, plugin=False):
    """Accept only complete CLI-owned sections plus separator blank lines.

    Only the official CLI's bounded scalar spellings are accepted.
    Every preexisting nonblank byte and every unrelated comment must survive.
    A CLI failure is never permission to adopt its partially written config.
    """
    old = before[0] if before else b''
    new = after[0] if after else b''
    if tomllib is None:
        raise Rejected('namespace_tool_requires_python311')
    prior = tomllib.loads(old.decode('utf-8'))
    actual = tomllib.loads(new.decode('utf-8'))
    desired = copy.deepcopy(prior)
    marketplaces = actual.get('marketplaces', {})
    entry = marketplaces.get(namespace, {}) if isinstance(marketplaces, dict) else {}
    source = entry.get('source') if isinstance(entry, dict) else None
    if not _same_cli_source(source, str(wrapper)):
        raise Rejected('unattributed_config_delta')
    additions = {'marketplaces': {namespace: {'source_type': 'local', 'source': source}}}
    if plugin:
        additions['plugins'] = {'context-guard@' + namespace: {'enabled': True}}
    for table, entries in additions.items():
        target = desired.setdefault(table, {})
        if not isinstance(target, dict) or any(key in target for key in entries):
            raise Rejected('existing_namespace_configuration')
        target.update(entries)
    if actual != desired:
        raise Rejected('unattributed_config_delta')
    marketplace = re.compile(
        rb'(?m)^\[marketplaces\.' + namespace.encode() +
        rb'\]\nsource_type = (?:"local"|\'local\')\n'
        rb'source = (?:"[^"\r\n]*"|\'[^\'\r\n]*\')\n')
    matches = list(marketplace.finditer(new))
    if len(matches) != 1:
        raise Rejected('unattributed_config_delta')
    sections = [matches[0].group()]
    if plugin:
        sections.append(f'[plugins."context-guard@{namespace}"]\nenabled = true\n'.encode())
    remainders = {new}
    for raw in sections:
        if raw in old or new.count(raw) != 1:
            raise Rejected('unattributed_config_delta')
        candidates = set()
        for remainder in remainders:
            if remainder.count(raw) != 1:
                continue
            left, right = remainder.split(raw, 1)
            # Only an inserted table's adjacent separator may be removed.
            for prefix in (left, left[:-1]) if left.endswith(b'\n') else (left,):
                for suffix in (right, right[1:]) if right.startswith(b'\n') else (right,):
                    candidates.add(prefix + suffix)
        remainders = candidates
    if old not in remainders:
        raise Rejected('unattributed_config_delta')
    if before and after and before[1] != after[1]:
        raise Rejected('unattributed_config_mode_change')
    return after


def _same_cli_source(observed, expected):
    """Accept only the Windows extended spelling of the same local drive path."""
    if not isinstance(observed, str):
        return False
    if observed == expected:
        return True
    if not observed.startswith('\\\\?\\'):
        return False
    ordinary = observed[4:]
    if (not re.fullmatch(r'[A-Za-z]:\\[^\r\n]*', ordinary)
            or not re.fullmatch(r'[A-Za-z]:\\[^\r\n]*', expected)
            or '..' in ntpath.normpath(ordinary).split('\\')
            or '..' in ordinary.split('\\')
            or ordinary != expected):
        return False
    return True


def authorized_home(record, pin, subject, home):
    """Validate operator-supplied scope; this record does not grant authority.

    The caller still needs user/host authorization. No credentials are read.
    A different target, tool revision, binary or source requires a new record.
    """
    if record is None and pin is None:
        return False
    daily = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
    if record is None or pin is None or home in (Path.home() / '.codex', daily):
        raise Rejected('explicit_private_target_required')
    record = safe_path(record)
    if home == record or home in record.parents:
        raise Rejected('scope_record_must_be_outside_target_home')
    raw = read(record)
    if digest(raw) != pin:
        raise Rejected('authorization_pin_mismatch')
    value = decode(raw)
    if (value.get('schema') != 'candidate-home-scope/v1'
            or value.get('purpose') != 'existing_private_acceptance_home'
            or value.get('subject') != subject):
        raise Rejected('authorization_target_mismatch')
    start, end = value.get('not_before'), value.get('expires_at')
    if (type(start) not in (int, float) or type(end) not in (int, float)
            or not 0 < end - start <= 86400 or not start <= time.time() < end):
        raise Rejected('authorization_expired_or_invalid')
    return True


def require_idle_home(home):
    """Bounded native open-file observation, not a security/exclusivity proof."""
    if sys.platform == 'win32':
        _require_windows_home_without_conflicting_handles(home)
        return
    if sys.platform != 'darwin':
        raise Rejected('authenticated_home_observation_unavailable')
    result = subprocess.run(['/usr/sbin/lsof', '-nP', '+D', str(home), '-F', 'p'],
                            capture_output=True, timeout=30, check=False)
    if result.returncode not in (0, 1) or result.stderr:
        raise Rejected('home_activity_observation_unknown')
    rows = result.stdout.decode('ascii').splitlines()
    if any(not re.fullmatch(r'p[0-9]+', row) for row in rows):
        raise Rejected('home_activity_observation_unknown')
    if any(int(row[1:]) != os.getpid() for row in rows):
        raise Rejected('target_home_has_active_process')


def _windows_home_entries(home, *, deadline, max_entries=8192):
    """List a bounded, non-reparse tree without reading file contents."""
    pending = [safe_path(home)]
    entries = []
    while pending:
        if time.monotonic() >= deadline or len(entries) + len(pending) > max_entries:
            raise Rejected('home_activity_observation_unknown')
        path = safe_path(pending.pop())
        try:
            info = path.stat(follow_symlinks=False)
            if (getattr(info, 'st_file_attributes', 0) & 0x400
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
                raise Rejected('home_activity_observation_unknown')
            is_dir = stat.S_ISDIR(info.st_mode)
            entries.append((path, is_dir))
            if is_dir:
                with os.scandir(path) as listing:
                    children = []
                    for item in listing:
                        if (time.monotonic() >= deadline
                                or len(entries) + len(pending) + len(children) >= max_entries):
                            raise Rejected('home_activity_observation_unknown')
                        children.append(Path(item.path))
                pending.extend(children)
        except (OSError, ValueError) as exc:
            raise Rejected('home_activity_observation_unknown') from exc
    return entries


class _WindowsFileApi:
    """Narrow injectable Win32 surface; no process or credential enumeration."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.invalid_handle = ctypes.c_void_p(-1).value
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.create = kernel.CreateFileW
        self.create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE)
        self.create.restype = wintypes.HANDLE
        self.close = kernel.CloseHandle
        self.close.argtypes = (wintypes.HANDLE,)
        self.close.restype = wintypes.BOOL
        self.information = kernel.GetFileInformationByHandleEx
        self.information.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                     wintypes.DWORD)
        self.information.restype = wintypes.BOOL
        class AttributeTag(ctypes.Structure):
            _fields_ = [('attributes', wintypes.DWORD), ('reparse_tag', wintypes.DWORD)]
        self.attribute_tag = AttributeTag

    def attributes(self, handle):
        observed = self.attribute_tag()
        if not self.information(handle, 9, self.ctypes.byref(observed),
                                self.ctypes.sizeof(observed)):
            raise Rejected('home_activity_observation_unknown')
        return observed.attributes

    def last_error(self):
        return self.ctypes.get_last_error()


def _win32_open_exclusive(path, is_dir, api):
    """Observe conflicting data/list handles on one existing path."""
    flags = 0x00200000 | (0x02000000 if is_dir else 0)
    handle = api.create(str(path), 0x0001, 0, None, 3, flags, None)
    if handle == api.invalid_handle:
        if api.last_error() == 32:
            raise Rejected('target_home_has_active_process')
        raise Rejected('home_activity_observation_unknown')
    try:
        _verify_opened_windows_attributes(api.attributes(handle), is_dir)
    finally:
        if not api.close(handle):
            raise Rejected('home_activity_observation_unknown')


def _verify_opened_windows_attributes(attributes, is_dir):
    if (attributes & 0x400 or bool(attributes & 0x10) != is_dir):
        raise Rejected('home_activity_observation_unknown')


def _require_windows_home_without_conflicting_handles(home, *, api=None):
    """Advisory scan of enumerable conflicts, not a hard-timeout or global idle proof."""
    deadline = time.monotonic() + 20
    entries = _windows_home_entries(home, deadline=deadline)
    api = api or _WindowsFileApi()
    for path, is_dir in entries:
        if time.monotonic() >= deadline:
            raise Rejected('home_activity_observation_unknown')
        _win32_open_exclusive(path, is_dir, api)
    if time.monotonic() >= deadline:
        raise Rejected('home_activity_observation_unknown')


def install(*, root, home, transaction, manifest, source_pin, runtime_pin, namespace, binary,
            binary_pin, apply=False, cli_factory=CLI, authorization=None,
            authorization_pin=None, idle_checker=require_idle_home):
    root, home, transaction, binary = map(safe_path, (root, home, transaction, binary))
    if tomllib is None:
        raise Rejected('namespace_tool_requires_python311')
    if not home.is_dir():
        raise Rejected('existing_isolated_home_required')
    ownership = safe_path(home / '.candidate-namespace-transaction.lock')
    if ownership.exists():
        raise Rejected('concurrent_namespace_writer')
    if (not re.fullmatch(r'cg-candidate-[a-z0-9][a-z0-9-]{0,40}', namespace)
            or home == root or root in home.parents or home in root.parents
            or transaction == root or root in transaction.parents
            or transaction == home or home in transaction.parents
            or transaction in root.parents or transaction in home.parents):
        raise Rejected('invalid_namespace_or_transaction_scope')
    if authorization is not None and root in safe_path(authorization).parents:
        raise Rejected('private_scope_record_in_public_source')
    files, version = source_manifest(root, manifest, source_pin, runtime_pin)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', version):
        raise Rejected('unsafe_version')
    binary_sha = executable_digest(binary)
    if binary_sha != binary_pin:
        raise Rejected('binary_pin_mismatch')
    subject = {'schema': 'candidate-namespace-install/v1', 'namespace': namespace,
               'source_tree_sha256': source_pin, 'runtime_tree_sha256': runtime_pin,
               'installer_sha256': digest(read(Path(__file__).resolve())),
               'binary_sha256': binary_sha, 'home': str(home), 'version': version}
    scoped = authorized_home(authorization, authorization_pin, subject, home)
    if scoped:
        subject = {**subject, 'authorization_sha256': authorization_pin}
    cache = safe_path(home / 'plugins/cache' / namespace / 'context-guard')
    archive = safe_path(home / 'plugins/cache-archive' / namespace / 'context-guard')
    product = transaction / 'marketplace/product'
    receipt = transaction / 'receipt.json'
    config = home / 'config.toml'
    if receipt.exists():
        for path in (cache / version, archive / version, product):
            safe_path(path)
        saved = decode(read(receipt))
        if saved.get('subject') != subject or saved.get('status') != 'installed':
            raise Rejected('receipt_subject_mismatch')
        if (manager.full_file_manifest(cache / version) != files
                or manager.full_file_manifest(product) != files
                or manager.full_file_manifest(archive / version) != files):
            raise Rejected('consumed_cache_changed')
        manager.audit_cache_archive(cache, archive, repair=False)
        if digest(read(config) if config.exists() else b'') != saved['config_sha256']:
            raise Rejected('config_changed_since_install')
        return {'status': 'strict_noop', 'subject': subject, 'model_calls': 0}
    if transaction.exists() or cache.parent.exists() or archive.parent.exists():
        raise Rejected('existing_or_incomplete_target')
    cli = cli_factory(binary, home)
    status = cli.call('login', 'status', json_result=False, allowed=(0, 1))
    if scoped:
        if 'Logged in using ChatGPT' not in status:
            raise Rejected('authorized_existing_home_auth_state_changed')
        idle_checker(home)
    elif 'Not logged in' not in status:
        raise Rejected('only_unauthenticated_test_home_supported')
    marketplaces = cli.call('plugin', 'marketplace', 'list', '--json')
    if any(row.get('name') == namespace for row in marketplaces.get('marketplaces', [])):
        raise Rejected('marketplace_already_registered')
    if not apply:
        return {'status': 'inputs_ready', 'subject': subject, 'model_calls': 0}
    home.mkdir(parents=True, exist_ok=True)
    try:
        ownership.mkdir()
    except FileExistsError as exc:
        raise Rejected('concurrent_namespace_writer') from exc
    try:
        if scoped:
            idle_checker(home)
        if transaction.exists() or cache.parent.exists() or archive.parent.exists():
            raise Rejected('target_appeared_before_lock')
        before = config_snapshot(config)
        expected = before
        old = old_cache_snapshot(home, namespace)
        transaction.mkdir(parents=True)
        write_new(transaction / 'started.json', subject)
    except BaseException:
        ownership.rmdir()
        raise
    stage = 'cache_install_lock'
    prior_stage = None
    try:
        with manager.cache_install_lock(cache):
            stage = 'staging_source'
            product.mkdir(parents=True)
            for name, sha in files.items():
                target = product / name
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = read(root / name)
                if digest(raw) != sha:
                    raise Rejected('source_changed_during_staging')
                with target.open('xb') as stream:
                    stream.write(raw)
            if manager.full_file_manifest(product) != files:
                raise Rejected('staged_source_mismatch')
            wrapper = product.parent / '.agents/plugins/marketplace.json'
            wrapper.parent.mkdir(parents=True)
            write_new(wrapper, {'name': namespace, 'plugins': [{
                'name': 'context-guard', 'source': {'source': 'local', 'path': './product'},
                'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'}}]})
            try:
                if scoped:
                    idle_checker(home)
                stage = 'marketplace_add'
                added = cli.call('plugin', 'marketplace', 'add', str(product.parent), '--json')
                observed = config_snapshot(config)
                stage = 'marketplace_config_delta'
                expected = namespace_config_delta(before, observed, namespace, product.parent)
                write_new(transaction / 'marketplace-config-delta.json', {
                    'before_sha256': digest(before[0] if before else b''),
                    'after_sha256': digest(observed[0] if observed else b''),
                    'allowed_sections': ['marketplaces.' + namespace]})
                # Read back the registered source, not just the add acknowledgment.
                stage = 'marketplace_readback'
                rows = cli.call('plugin', 'marketplace', 'list', '--json').get('marketplaces', [])
                matching = [r for r in rows if r.get('name') == namespace]
                if (not isinstance(added, dict) or len(matching) != 1
                        or not _same_cli_source(matching[0].get('root'), str(product.parent))):
                    raise Rejected('marketplace_readback_mismatch')
                stage = 'plugin_add'
                installed = cli.call('plugin', 'add', 'context-guard@' + namespace, '--json')
                observed = config_snapshot(config)
                stage = 'plugin_config_delta'
                expected = namespace_config_delta(before, observed, namespace, product.parent, plugin=True)
                write_new(transaction / 'plugin-config-delta.json', {
                    'before_sha256': digest(before[0] if before else b''),
                    'after_sha256': digest(observed[0] if observed else b''),
                    'allowed_sections': ['marketplaces.' + namespace, 'plugins.context-guard@' + namespace]})
                stage = 'plugin_readback'
                if any(installed.get(k) != v for k, v in {
                    'pluginId': 'context-guard@' + namespace, 'name': 'context-guard',
                    'marketplaceName': namespace, 'version': version,
                    }.items()) or not _same_cli_source(
                        installed.get('installedPath'), str(cache / version)):
                    raise Rejected('installed_path_or_identity_mismatch')
                stage = 'cache_parity'
                safe_path(cache / version)
                if manager.full_file_manifest(cache / version) != files:
                    raise Rejected('installed_full_source_mismatch')
                manager.require_cache_parity(product, cache / version, version, same_version=True)
                stage = 'archive_current'
                manager.archive_verified_current_version(product, cache, archive, version)
            finally:
                stage_before_restore = stage
                prior_stage = stage_before_restore
                stage = 'config_restore'
                try:
                    restore_config(config, before, expected)
                except Rejected:
                    current = config_snapshot(config)
                    write_new(transaction / 'incomplete.json', {
                        'status': 'incomplete', 'reason': 'unattributed_config_change_preserved',
                        'before_sha256': digest(before[0] if before else b''),
                        'last_attributed_sha256': digest(expected[0] if expected else b''),
                        'retained_sha256': digest(current[0] if current else b''),
                        'automatic_restore': False})
                    raise
                stage = stage_before_restore
            stage = 'post_install_verify'
            if old_cache_snapshot(home, namespace) != old:
                raise Rejected('old_cache_changed')
            if executable_digest(binary) != binary_sha:
                raise Rejected('executable_changed')
            manager.audit_cache_archive(cache, archive, repair=False)
            result = {'status': 'installed', 'subject': subject, 'model_calls': 0,
                      'config_sha256': digest(before[0] if before else b''),
                      'old_cache_bytes_and_mtimes_preserved': True,
                      'runtime_files': len(manager.tree_manifest(product)),
                      'activation_overrides': {
                          f'marketplaces.{namespace}.source_type': 'local',
                          f'marketplaces.{namespace}.source': str(product.parent),
                          f'plugins.context-guard@{namespace}.enabled': True,
                          'plugins.context-guard@codex-context-guard.enabled': False},
                      'native_acceptance': 'not_established', 'automatic_cleanup': False}
            write_new(receipt, result)
            return result
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        # No exception text, CLI output or configuration content enters this receipt.
        if transaction.is_dir() and not (transaction / 'failure.json').exists():
            code = str(exc) if isinstance(exc, Rejected) else ''
            if code not in {'unattributed_config_delta', 'unattributed_config_mode_change',
                            'concurrent_config_change_not_overwritten',
                            'official_cli_failed', 'marketplace_readback_mismatch',
                            'installed_path_or_identity_mismatch'}:
                code = 'other_failure'
            write_new(transaction / 'failure.json', {
                'status': 'failed', 'stage': stage, 'prior_stage': prior_stage,
                'reason': code,
                'exception_class': type(exc).__name__,
                'automatic_retry': False, 'model_calls': 0})
        raise
    finally:
        ownership.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'home', 'transaction', 'manifest', 'binary'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-pin', 'runtime-pin', 'namespace', 'binary-pin'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--authorization', type=Path,
                        help='Private operator scope record; does not itself grant permission')
    parser.add_argument('--authorization-pin', help='Exact SHA256 of the reviewed scope record')
    args = vars(parser.parse_args())
    try:
        result = install(**args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print('candidate_install=failed; retained_state_requires_inspection')
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
