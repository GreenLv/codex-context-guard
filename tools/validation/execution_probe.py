"""Probe the invoking Python process only; never grant or widen permissions.

Invoke through the actual restricted route used for the future child. A result
cannot certify a different parent, shell, sandbox, login, ACL or model route.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def probe(cwd: Path, fixture: Path, witnesses: list[Path]) -> dict:
    checks = {}
    checks['cwd_matches'] = Path.cwd().resolve() == cwd.resolve()
    checks['python_310_plus'] = sys.version_info >= (3, 10)
    checks['fixture_write_read_cleanup'] = False
    checks['witnesses_readable'] = False
    checks['git_initial_commit_readable'] = False
    if checks['cwd_matches']:
        try:
            # The real process, rather than a parent access() prediction,
            # creates, flushes, reopens and removes its own unique witness.
            with tempfile.TemporaryDirectory(prefix='.cg-probe-', dir=fixture) as name:
                path = Path(name) / 'witness'
                with path.open('xb') as handle:
                    handle.write(b'context-guard-probe\n')
                    handle.flush()
                    os.fsync(handle.fileno())
                checks['fixture_write_read_cleanup'] = path.read_bytes() == b'context-guard-probe\n'
            checks['fixture_write_read_cleanup'] &= not Path(name).exists()
        except OSError:
            checks['fixture_write_read_cleanup'] = False
        try:
            checks['witnesses_readable'] = bool(witnesses) and all(
                not p.is_symlink() and p.is_file() and p.stat().st_size <= 8*1024*1024
                and hashlib.sha256(p.read_bytes()).hexdigest() for p in witnesses)
        except OSError:
            pass
        try:
            result = subprocess.run(['git', '-C', str(fixture), 'cat-file', '-e', 'HEAD^{commit}'],
                                    capture_output=True, timeout=10, check=False)
            checks['git_initial_commit_readable'] = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {'schema': 'cg-execution-probe/v1', 'status': 'passed' if all(checks.values()) else 'failed',
            'checks': checks, 'subject': 'invoking_process_only',
            'other_route_permissions': 'unknown', 'official_hook_trust': 'unknown',
            'powershell_language_mode': 'not_probed', 'model_requests': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cwd', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--witness', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    # Reject an occupied output before even temporary probe mutations.
    if args.output.exists() or args.output.is_symlink():
        parser.error('output_exists')
    result = probe(args.cwd, args.fixture, args.witness)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(result, handle, indent=2)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
