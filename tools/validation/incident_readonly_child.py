"""Actual restricted-tool child witness on an immutable copied session.

Run only on a collector-owned fixture, never on live plugin state. Raw query
output and token-bearing argv remain private. Mode bits are not Windows ACLs.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import stat
import struct
import subprocess
from pathlib import Path

SCHEMA = 'incident-readonly-child/v1'


class RestrictionError(OSError):
    def __init__(self, record):
        super().__init__('fixture restriction unavailable; inspect retained record')
        self.record = record


def inventory(root):
    result = {}
    total = 0
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('special fixture entry')
        if stat.S_ISDIR(info.st_mode):
            result[path.relative_to(root).as_posix()] = {'kind': 'directory', 'mode': info.st_mode,
                                                       'mtime_ns': info.st_mtime_ns, 'inode': info.st_ino}
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > 128 * 1024 * 1024:
                raise ValueError('fixture budget')
            result[path.relative_to(root).as_posix()] = {
                'kind': 'file', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'size': info.st_size, 'mtime_ns': info.st_mtime_ns,
                'inode': info.st_ino, 'mode': info.st_mode}
    return result


def acl_argv(root, sid):
    # Specific write/delete bits exclude SYNCHRONIZE and READ_CONTROL.
    if not isinstance(sid, str) or not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+', sid):
        raise ValueError('invalid SID')
    bits = '(WD,AD,WEA,WA,DE,DC)' if root.is_dir() else '(WD,AD,WEA,WA,DE)'
    return [['icacls', str(root), '/deny', '*' + sid + ':' + bits]]


def fixture_paths(root):
    root = Path(root)
    paths = [root, *sorted(root.rglob('*'))]
    for path in paths:
        info = path.lstat()
        if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise ValueError('linked or special fixture')
    inventory(root)
    return paths


def windows_descriptor(path, descriptor=None):
    """Read/restore a self-relative DACL with its exact inheritance control."""
    from ctypes import wintypes
    info = Path(path).lstat()
    if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            or getattr(info, 'st_file_attributes', 0) & 0x400):
        raise ValueError('linked or special DACL target')
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    read = api.GetFileSecurityW
    read.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    read.restype = wintypes.BOOL
    if descriptor is None:
        size = wintypes.DWORD()
        read(str(path), 4, None, 0, ctypes.byref(size))
        if ctypes.get_last_error() != 122 or not 0 < size.value <= 65536:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size.value)
        if not read(str(path), 4, buffer, size.value, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return base64.b64encode(buffer.raw[:size.value]).decode('ascii')
    raw = base64.b64decode(descriptor, validate=True)
    if not 0 < len(raw) <= 65536:
        raise ValueError('invalid saved DACL')
    buffer = ctypes.create_string_buffer(raw)
    strategy, flags = restoration_strategy(descriptor)
    if strategy == 'raw-explicit':
        write = api.SetFileSecurityW
        write.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
        write.restype = wintypes.BOOL
        if not write(str(path), flags, buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    # The saved descriptor already uses automatic inheritance. Reapply that
    # model with its original protection setting, never convert a non-AI ACL.
    acl = ctypes.c_void_p()
    present, defaulted = wintypes.BOOL(), wintypes.BOOL()
    get_dacl = api.GetSecurityDescriptorDacl
    get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    get_dacl.restype = wintypes.BOOL
    if not get_dacl(buffer, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not present.value or not acl.value:
        raise ValueError('missing saved DACL')
    write = api.SetNamedSecurityInfoW
    write.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    write.restype = wintypes.DWORD
    error = write(str(path), 1, flags, None, None, acl, None)
    if error:
        raise ctypes.WinError(error)


def restoration_strategy(descriptor):
    """Choose the saved inheritance model before any fixture mutation."""
    control = descriptor_contract(descriptor)['dacl_control']
    if control not in (4, 0x404, 0x1004, 0x1404):
        raise ValueError('unsupported original DACL control model')
    if control & 0x400:
        return 'auto-inherited', 4 | (0x80000000 if control & 0x1000 else 0x20000000)
    return 'raw-explicit', 4


def descriptor_contract(descriptor):
    """Ordered complete ACE bytes and DACL controls, independent of SD layout."""
    raw = base64.b64decode(descriptor, validate=True)
    if not 20 <= len(raw) <= 65536:
        raise ValueError('invalid descriptor bounds')
    revision, _, control, _, _, _, offset = struct.unpack_from('<BBHIIII', raw)
    if revision != 1 or not control & 0x8000 or not control & 4 or not 20 <= offset <= len(raw) - 8:
        raise ValueError('invalid self-relative DACL')
    acl_revision, _, size, count, _ = struct.unpack_from('<BBHHH', raw, offset)
    if acl_revision not in (2, 4) or size < 8 or offset + size > len(raw):
        raise ValueError('invalid DACL bounds')
    pos = offset + 8
    aces = []
    for _ in range(count):
        if pos + 4 > offset + size:
            raise ValueError('invalid ACE header')
        length = struct.unpack_from('<H', raw, pos + 2)[0]
        if length < 4 or length % 4 or pos + length > offset + size:
            raise ValueError('invalid ACE bounds')
        aces.append(raw[pos:pos + length].hex())
        pos += length
    # Ignore unused ACL allocation/padding and unrelated SD offsets, never an
    # ACE byte, mask, principal, condition, order or inheritance-control bit.
    return {'descriptor_revision': revision, 'dacl_revision': acl_revision,
            'dacl_control': control & ~0x8000, 'aces': aces}



def check_fixture_identity(root, record):
    paths = fixture_paths(root)
    observed = {str(p): [p.lstat().st_dev, p.lstat().st_ino] for p in paths}
    if observed != {k: list(v) for k, v in record['objects'].items()}:
        raise ValueError('fixture object identity changed')


def windows_restrict(root, *, sid=None):
    root = Path(root).absolute()
    paths = fixture_paths(root)
    collector_sid = current_sid()
    sid = collector_sid if sid is None else sid
    acl_argv(root, sid)  # Validate the principal before any mutation.
    record = {'family': 'windows-acl', 'policy': 'specific-write-deny/v2',
              'root': str(root), 'sid': sid, 'collector_sid': collector_sid, 'commands': [],
              'original_dacls': {str(p): windows_descriptor(p) for p in paths},
              'original_inventory': inventory(root),
              'objects': {str(p): (p.lstat().st_dev, p.lstat().st_ino) for p in paths}}
    record['original_restore_strategies'] = {name: restoration_strategy(descriptor)
                                             for name, descriptor in record['original_dacls'].items()}
    # All unsupported controls/NULL shapes reject before any ACL command.
    try:
        for path in sorted(paths, key=lambda p: (-len(p.parts), str(p))):
            check_fixture_identity(root, record)
            for argv in acl_argv(path, sid):
                result = subprocess.run(argv, capture_output=True, timeout=30, check=False)
                record['commands'].append({'argv': argv, 'exit_code': result.returncode,
                                           'output': (result.stdout + result.stderr).decode(errors='replace')})
                if result.returncode:
                    raise OSError('fixture DACL application failed')
        if inventory(root) != record['original_inventory']:
            raise ValueError('fixture bytes or stat changed during restriction')
        return record
    except (Exception, KeyboardInterrupt) as exc:
        record['application_error'] = type(exc).__name__
        try:
            restore(root, record)
            record['restoration'] = 'verified'
        except Exception as restoration:
            record['restoration_error'] = type(restoration).__name__
        raise RestrictionError(record) from exc


def current_sid():
    raw = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'],
                                  text=True, timeout=10)
    import csv
    return next(csv.reader([raw.strip()]))[1]


def restrict(root, *, sid=None):
    """Return restoration metadata; failures are retained, never a pass."""
    if os.name == 'nt':
        return windows_restrict(root, sid=sid)
    record = {'family': 'posix-mode', 'modes': {}}
    for path in [*sorted(root.rglob('*'), reverse=True), root]:
        if path.is_symlink():
            raise ValueError('linked fixture')
        record['modes'][str(path)] = stat.S_IMODE(path.stat().st_mode)
        path.chmod(0o500 if path.is_dir() else 0o400)
    return record


def restore(root, record):
    if record['family'] == 'windows-acl':
        root = Path(root).absolute()
        paths = fixture_paths(root)
        if (record.get('policy') != 'specific-write-deny/v2'
                or record.get('root') != str(root) or record.get('collector_sid') != current_sid()
                or set(record.get('original_dacls', {})) != {str(p) for p in paths}):
            raise ValueError('restoration scope or principal differs')
        check_fixture_identity(root, record)
        # Restore traversal first, then descendants, preserving original DACLs.
        failures = []
        for path in sorted(paths, key=lambda p: (len(p.parts), str(p))):
            try:
                check_fixture_identity(root, record)
                windows_descriptor(path, record['original_dacls'][str(path)])
            except Exception as exc:
                failures.append(type(exc).__name__)
        if failures:
            raise OSError('DACL restoration incomplete: ' + ','.join(failures))
        readback = {str(path): windows_descriptor(path) for path in paths}
        differences = {name: {'before': descriptor_contract(record['original_dacls'][name]),
                              'after': descriptor_contract(observed)}
                       for name, observed in readback.items()
                       if descriptor_contract(observed) != descriptor_contract(record['original_dacls'][name])}
        if differences:
            record['restoration_readback'] = readback
            record['restoration_differences'] = differences
            raise ValueError('restored DACL or inheritance controls differ')
        if inventory(root) != record['original_inventory']:
            raise ValueError('fixture bytes or stat differ after restoration')
    else:
        for name, mode in record['modes'].items():
            Path(name).chmod(mode)


def witness(request):
    if request.get('schema') != 'incident-readonly-request/v1':
        raise ValueError('wrong request schema')
    root = Path(request['fixture']).resolve(strict=True)
    argv = request['argv']
    if not isinstance(argv, list) or not all(isinstance(v, str) for v in argv):
        raise ValueError('invalid argv')
    if len(argv) < 4 or argv[2] != 'checkpoint-status' or '--commands' not in argv:
        raise ValueError('not a commands query')
    before = inventory(root)
    if before != request['inventory']:
        raise ValueError('fixture changed before child')
    attempts = []
    # Actual denied operations, including the writer's lock-open failure shape.
    for target in (root / 'denied-new-file', Path(request['lock'])):
        try:
            with target.open('ab') as stream:
                stream.write(b'write-denial-witness')
            attempts.append({'errno': 0})
        except OSError as exc:
            attempts.append({'errno': exc.errno})
    p = subprocess.run(argv, capture_output=True, timeout=30, check=False,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return {'schema': SCHEMA, 'request_sha256': request['request_sha256'],
            'platform': platform.system(), 'pid': os.getpid(), 'ppid': os.getppid(),
            'euid': os.geteuid() if hasattr(os, 'geteuid') else None,
            'sid': current_sid() if os.name == 'nt' else None,
            'write_attempts': attempts, 'before': before, 'after': inventory(root),
            'cli_exit_code': p.returncode,
            'query_stdout': p.stdout.decode(errors='replace'),
            'query_stderr': p.stderr.decode(errors='replace')}


def judge(record, request):
    if record.get('schema') != SCHEMA:
        raise ValueError('wrong child schema')
    expected = hashlib.sha256(json.dumps({k: v for k, v in request.items() if k != 'request_sha256'},
                                        ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if request['request_sha256'] != expected:
        raise ValueError('request digest invalid')
    if record.get('request_sha256') != request['request_sha256']:
        raise ValueError('unbound child')
    for field in ('pid', 'ppid', 'cli_exit_code'):
        if type(record.get(field)) is not int:
            raise ValueError('invalid child integer')
    if record['pid'] <= 0 or record['ppid'] <= 0:
        raise ValueError('invalid child identity')
    if record['platform'] not in ('Darwin', 'Linux', 'Windows'):
        raise ValueError('unknown child platform')
    if record['platform'] == 'Windows':
        if not isinstance(record.get('sid'), str) or record['sid'] != request['restriction']['sid']:
            raise ValueError('child principal differs')
    elif type(record.get('euid')) is not int or record['euid'] == 0:
        return 'pending'
    writes = record.get('write_attempts')
    if not isinstance(writes, list) or len(writes) != 2:
        raise ValueError('missing write witness')
    if any(type(x.get('errno')) is not int for x in writes):
        raise ValueError('invalid write errno')
    if any(x['errno'] not in (errno.EACCES, errno.EPERM) for x in writes):
        return 'failed'
    if record['before'] != request['inventory'] or record['after'] != record['before']:
        return 'failed'
    if record['cli_exit_code'] != 0:
        return 'failed'
    query = json.loads(record['query_stdout'])
    if (not isinstance(query.get('advanced_commands'), dict)
            or query.get('turn_id') != request['turn']
            or query.get('revision') != request['state_revision']):
        raise ValueError('commands output missing')
    return 'passed'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--request', type=Path)
    group.add_argument('--identity', action='store_true')
    a = p.parse_args()
    if a.identity:
        if os.name != 'nt':
            raise ValueError('Windows tool principal required')
        print(json.dumps({'schema': 'incident-child-principal/v1', 'sid': current_sid(),
                          'pid': os.getpid(), 'platform': platform.system()}))
        return 0
    request = json.loads(a.request.read_text())
    value = witness(request)
    print(json.dumps(value, ensure_ascii=True))
    return 0 if judge(value, request) == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
