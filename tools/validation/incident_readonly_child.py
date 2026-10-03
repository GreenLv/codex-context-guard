"""Actual restricted-tool child witness on an immutable copied session.

Run only on a collector-owned fixture, never on live plugin state. Raw query
output and token-bearing argv remain private. Mode bits are not Windows ACLs.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import stat
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


def acl_argv(root, sid, *, restore=False):
    # Explicit deny scoped to a new fixture. No administrator or token change.
    if not sid.startswith('S-1-') or not all(c in 'S-0123456789' for c in sid):
        raise ValueError('invalid SID')
    if restore:
        return [['icacls', str(root), '/remove:d', '*' + sid, '/T'],
                ['icacls', str(root), '/grant:r', '*' + sid + ':(OI)(CI)F', '/T']]
    return [['icacls', str(root), '/inheritance:r',
             '/grant:r', '*' + sid + ':(OI)(CI)RX',
             '/deny', '*' + sid + ':(OI)(CI)(W,D)', '/T']]


def current_sid():
    raw = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'],
                                  text=True, timeout=10)
    import csv
    return next(csv.reader([raw.strip()]))[1]


def restrict(root):
    """Return restoration metadata; failures are retained, never a pass."""
    if os.name == 'nt':
        sid = current_sid()
        record = {'family': 'windows-acl', 'sid': sid, 'commands': []}
        for argv in acl_argv(root, sid):
            p = subprocess.run(argv, capture_output=True, timeout=30, check=False)
            record['commands'].append({'argv': argv, 'exit_code': p.returncode,
                                       'output': (p.stdout + p.stderr).decode(errors='replace')})
            if p.returncode:
                # Remove only our fixture deny, even after partial application.
                try:
                    restore(root, record)
                except Exception as exc:
                    record['restoration_error'] = type(exc).__name__
                raise RestrictionError(record)
        return record
    record = {'family': 'posix-mode', 'modes': {}}
    for path in [*sorted(root.rglob('*'), reverse=True), root]:
        if path.is_symlink():
            raise ValueError('linked fixture')
        record['modes'][str(path)] = stat.S_IMODE(path.stat().st_mode)
        path.chmod(0o500 if path.is_dir() else 0o400)
    return record


def restore(root, record):
    if record['family'] == 'windows-acl':
        for argv in acl_argv(root, record['sid'], restore=True):
            subprocess.run(argv, capture_output=True, timeout=30, check=True)
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
    p.add_argument('--request', type=Path, required=True)
    a = p.parse_args()
    request = json.loads(a.request.read_text())
    value = witness(request)
    print(json.dumps(value, ensure_ascii=True))
    return 0 if judge(value, request) == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
