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
import tempfile
from pathlib import Path

SCHEMA = 'incident-readonly-child/v1'


class RestrictionError(OSError):
    def __init__(self, record):
        super().__init__('fixture restriction unavailable; inspect retained record')
        self.record = record


class DACLWriteError(OSError):
    def __init__(self, result):
        super().__init__('native DACL write failed')
        self.native_result = result


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
        result = int(write(str(path), flags, buffer))
        observed = {'api': 'SetFileSecurityW', 'security_information': flags,
                    'return_value': result, 'winerror': 0 if result else ctypes.get_last_error()}
        if not result:
            raise DACLWriteError(observed)
        return observed
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
    observed = {'api': 'SetNamedSecurityInfoW', 'security_information': flags,
                'return_value': int(error), 'winerror': int(error)}
    if error:
        raise DACLWriteError(observed)
    return observed


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
    if any(p.is_file() and p.lstat().st_nlink != 1 for p in paths):
        raise ValueError('fixture hardlink identity drift')
    observed = {str(p): [p.lstat().st_dev, p.lstat().st_ino] for p in paths}
    if observed != {k: list(v) for k, v in record['objects'].items()}:
        raise ValueError('fixture object identity changed')


READ_BASELINE_POLICY = 'read-baseline-specific-write-deny/v3'


def durable_snapshot(path, record):
    # Hash the exact exclusive binary write, independent of text newline rules.
    raw = (json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    with Path(path).open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('snapshot write incomplete')
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def read_grant_argv(path, sid):
    acl_argv(path, sid)  # Reuse strict SID validation, never the collector as substitute.
    bits = '(RD,REA,RA,RC,S,X)' if Path(path).is_dir() else '(RD,REA,RA,RC,S)'
    return ['icacls', str(path), '/grant', '*' + sid + ':' + bits]


def ace_sid(raw):
    if len(raw) < 16 or raw[0] not in (0, 1):
        raise ValueError('unsupported v3 ACE shape')
    value = raw[8:]
    if value[0] != 1 or len(value) != 8 + 4 * value[1]:
        raise ValueError('invalid v3 ACE SID')
    authority = int.from_bytes(value[2:8], 'big')
    subs = struct.unpack('<' + 'I' * value[1], value[8:])
    return 'S-1-' + str(authority) + ''.join('-' + str(v) for v in subs)


def check_read_grant(before, after, sid, directory):
    old, new = descriptor_contract(before), descriptor_contract(after)
    mask = 0x1200a9 if directory else 0x120089
    def split(contract):
        actor, others = [], []
        for value in contract['aces']:
            raw = bytes.fromhex(value)
            (actor if ace_sid(raw) == sid and raw[0] == 0 else others).append(value)
        return actor, others
    old_actor, old_others = split(old)
    new_actor, new_others = split(new)
    if (old_others != new_others or old['dacl_revision'] != new['dacl_revision']
            or old['dacl_control'] != new['dacl_control']):
        raise ValueError('grant changed another principal or deny ACE')
    old_masks = {bytes.fromhex(v)[1]: struct.unpack_from('<I', bytes.fromhex(v), 4)[0]
                 for v in old_actor}
    new_masks = {bytes.fromhex(v)[1]: struct.unpack_from('<I', bytes.fromhex(v), 4)[0]
                 for v in new_actor}
    if len(old_masks) != len(old_actor) or len(new_masks) != len(new_actor):
        raise ValueError('ambiguous actor ACEs')
    if any(flags not in new_masks or new_masks[flags] & value != value
           or new_masks[flags] & ~(value | mask) for flags, value in old_masks.items()):
        raise ValueError('grant removed rights or added non-read rights')
    if any(flags not in old_masks and (flags != 0 or value != mask)
           for flags, value in new_masks.items()):
        raise ValueError('grant added unbounded actor rights')
    if new_masks.get(0, 0) & mask != mask:
        raise ValueError('grant lacks exact non-inheriting read baseline')


def check_write_deny(before, after, sid, *, directory):
    """Exact ordered /deny change, selected by the verified object's type.

    icacls inserts an explicit deny in the canonical explicit-deny block and
    removes only those bits from this actor's explicit grants. Existing ACEs
    retain byte identity/order apart from those exact mask changes. No OR
    aggregation accepts duplicate, split or reordered actor deny ACEs.
    """
    if type(directory) is not bool:
        raise ValueError('verified object type required')
    old, new = descriptor_contract(before), descriptor_contract(after)
    mask = 0x10156 if directory else 0x10116  # Directories additionally deny DC.
    if any(old[k] != new[k] for k in ('descriptor_revision', 'dacl_revision', 'dacl_control')):
        raise ValueError('deny changed DACL controls')
    def rank(raw):
        ace_sid(raw)  # Only supported ordinary allow/deny shapes.
        return (2 if raw[1] & 0x10 else 0) + (1 if raw[0] == 0 else 0)
    for contract in (old, new):
        ranks = [rank(bytes.fromhex(value)) for value in contract['aces']]
        if ranks != sorted(ranks):
            raise ValueError('noncanonical deny ACE order')
    expected, seen_flags, merged, actor_sid = [], set(), False, None
    for value in old['aces']:
        raw = bytearray.fromhex(value)
        actor = ace_sid(raw) == sid
        if actor:
            actor_sid = bytes(raw[8:])
        if actor and raw[0] == 1:
            if raw[1] in seen_flags:
                raise ValueError('ambiguous original actor deny ACEs')
            seen_flags.add(raw[1])
            if raw[1] == 0:
                struct.pack_into('<I', raw, 4, struct.unpack_from('<I', raw, 4)[0] | mask)
                merged = True
        elif actor and raw[0] == 0 and not raw[1] & 0x10:
            remaining = struct.unpack_from('<I', raw, 4)[0] & ~mask
            if not remaining:
                continue  # Exact zero-right explicit grant is removed by /deny.
            struct.pack_into('<I', raw, 4, remaining)
        expected.append(raw.hex())
    if merged:
        if new['aces'] != expected:
            raise ValueError('deny changed an ordered ACE or exact write mask')
    else:
        if actor_sid is None:
            raise ValueError('pinned actor grant unavailable before deny')
        added = (struct.pack('<BBHI', 1, 0, 8 + len(actor_sid), mask) + actor_sid).hex()
        if new['aces'].count(added) != 1:
            raise ValueError('deny missing exact unique write ACE')
        position = new['aces'].index(added)
        if (any(rank(bytes.fromhex(v)) != 0 for v in new['aces'][:position])
                or new['aces'][:position] + new['aces'][position + 1:] != expected):
            raise ValueError('deny changed ordered permissions beyond one exact ACE')


def sid_bytes(sid):
    if not isinstance(sid, str) or not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+', sid):
        raise ValueError('invalid actor SID')
    parts = list(map(int, sid.split('-')[2:]))
    if not 2 <= len(parts) <= 16 or not 0 <= parts[0] < 2 ** 48 or any(
            not 0 <= value < 2 ** 32 for value in parts[1:]):
        raise ValueError('actor SID bounds')
    if sid != 'S-1-' + '-'.join(map(str, parts)):
        raise ValueError('noncanonical actor SID')
    return bytes([1, len(parts) - 1]) + parts[0].to_bytes(6, 'big') + struct.pack(
        '<' + 'I' * (len(parts) - 1), *parts[1:])


def descriptor_with_aces(before, aces):
    """DACL-only SD; unrelated owner/group/SACL are never written by our API."""
    contract = descriptor_contract(before)
    body = b''.join(bytes.fromhex(value) for value in aces)
    if len(body) + 8 > 65535 or len(aces) > 65535:
        raise ValueError('planned ACL bounds')
    header = struct.pack('<BBHIIII', contract['descriptor_revision'], 0,
                         contract['dacl_control'] | 0x8000, 0, 0, 0, 20)
    acl = struct.pack('<BBHHH', contract['dacl_revision'], 0, len(body) + 8, len(aces), 0)
    return base64.b64encode(header + acl + body).decode('ascii')


def planned_acl_change(before, sid, phase, directory, policy=READ_BASELINE_POLICY):
    """Pure actor-only change; existing validators are never relaxed."""
    if (type(directory) is not bool or phase not in ('grant', 'deny')
            or policy not in (READ_BASELINE_POLICY, 'specific-write-deny/v2')
            or (phase == 'grant' and policy != READ_BASELINE_POLICY)):
        raise ValueError('unsupported ACL mutation policy or type')
    actor_bytes = sid_bytes(sid)
    restoration_strategy(before)
    old = descriptor_contract(before)
    ranks, seen, aces = [], set(), []
    actor_present, merged = False, False
    read_mask = 0x1200a9 if directory else 0x120089
    write_mask = 0x10156 if directory else 0x10116
    for value in old['aces']:
        raw = bytearray.fromhex(value)
        actor = ace_sid(raw) == sid
        ranks.append((2 if raw[1] & 0x10 else 0) + (1 if raw[0] == 0 else 0))
        if actor:
            actor_present = True
            key = (raw[0], raw[1])
            if key in seen:
                raise ValueError('ambiguous original actor ACEs')
            seen.add(key)
            mask = struct.unpack_from('<I', raw, 4)[0]
            if phase == 'grant' and raw[:2] == b'\x00\x00':
                struct.pack_into('<I', raw, 4, mask | read_mask)
                merged = True
            elif phase == 'deny' and raw[:2] == b'\x01\x00':
                struct.pack_into('<I', raw, 4, mask | write_mask)
                merged = True
            elif phase == 'deny' and raw[0] == 0 and not raw[1] & 0x10:
                remaining = mask & ~write_mask
                if not remaining:
                    continue
                struct.pack_into('<I', raw, 4, remaining)
        aces.append(raw.hex())
    if ranks != sorted(ranks):
        raise ValueError('noncanonical original ACL order')
    if not merged:
        ace_type, mask = (0, read_mask) if phase == 'grant' else (1, write_mask)
        added = (struct.pack('<BBHI', ace_type, 0, 8 + len(actor_bytes), mask) + actor_bytes).hex()
        position = (next((i for i, value in enumerate(aces)
                          if bytes.fromhex(value)[1] & 0x10), len(aces))
                    if phase == 'grant' else 0)
        aces.insert(position, added)
    planned = descriptor_with_aces(before, aces)
    if phase == 'grant':
        check_read_grant(before, planned, sid, directory)
    elif policy == READ_BASELINE_POLICY or actor_present:
        check_write_deny(before, planned, sid, directory=directory)
    # Legacy v2 allows an absent actor without a v3 read grant. Its exact
    # planned contract is checked below; do not fabricate a validator baseline.
    return planned


def write_windows_dacl(path, planned):
    return windows_descriptor(path, planned)


def check_native_result(result, planned):
    strategy, flags = restoration_strategy(planned)
    api = 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW'
    if (not isinstance(result, dict)
            or set(result) != {'api', 'security_information', 'return_value', 'winerror'}
            or result['api'] != api or result['security_information'] != flags
            or type(result['security_information']) is not int
            or type(result['return_value']) is not int or type(result['winerror']) is not int
            or result['winerror'] != 0
            or (not result['return_value'] if strategy == 'raw-explicit' else result['return_value'] != 0)):
        raise ValueError('native API result unavailable or unsuccessful')


def acl_failure(exc, phase, step):
    reasons = {'preflight': 'acl_preflight_failed', 'intent': 'acl_intent_persistence_failed',
               'write': 'native_dacl_write_failed', 'readback': 'dacl_readback_failed',
               'validate': 'exact_dacl_validation_failed',
               'observed': 'acl_observation_persistence_failed', 'receipt': 'acl_receipt_failed'}
    return {'phase': phase, 'step': step, 'reason': reasons.get(step, 'acl_transaction_failed'),
            'exception': type(exc).__name__, 'private_message': str(exc),
            'errno': getattr(exc, 'errno', None), 'winerror': getattr(exc, 'winerror', None)}


def operation_snapshot(record, operation, suffix):
    output = Path(record.get('operation_output') or record['ownership']['output'])
    if (not output.is_dir() or output.is_symlink()
            or [output.stat().st_dev, output.stat().st_ino] != record['operation_output_identity']):
        raise ValueError('private operation output unavailable')
    name = f"fixture-{operation['phase']}-op-{operation['sequence']:04d}-{suffix}.json"
    return durable_snapshot(output / name, operation)


def apply_acl_change(root, record, path, before, planned, phase, expected):
    """Persist actual after state before validation and before any rollback."""
    strategy, flags = restoration_strategy(planned)
    operation = {'sequence': len(record.setdefault('operations', [])) + 1,
                 'phase': phase, 'path': path.relative_to(root).as_posix(),
                 'sid': record['sid'], 'policy': record['policy'], 'directory': path.is_dir(),
                 'object_identity': list(record['objects'][str(path)]),
                 'selected_api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                 'security_information': flags,
                 'original_snapshot_sha256': record.get('original_snapshot_sha256'),
                 'before': before, 'planned': planned, 'actual': None,
                 'before_contract': descriptor_contract(before), 'planned_contract': descriptor_contract(planned),
                 'native_result': None, 'status': 'intent', 'step': 'preflight'}
    record['operations'].append(operation)
    step = 'preflight'
    try:
        verify_original_snapshot(record)
        if record['root'] != str(root) or record['collector_sid'] != current_sid():
            raise ValueError('ACL transaction scope or collector differs')
        check_fixture_identity(root, record)
        if descriptor_contract(planned) != descriptor_contract(planned_acl_change(
                before, record['sid'], phase, path.is_dir(), record['policy'])):
            raise ValueError('planned ACL differs from preconstructed exact target')
        actual = windows_descriptor(path)
        if descriptor_contract(actual) != descriptor_contract(before):
            raise ValueError('phase DACL changed before write')
        step = operation['step'] = 'intent'
        operation['intent_sha256'] = operation_snapshot(record, operation, 'intent')
        step = operation['step'] = 'write'
        try:
            operation['native_result'] = write_windows_dacl(path, planned)
        except BaseException as exc:
            operation['native_result'] = getattr(exc, 'native_result', None)
            # A failing API can still partially mutate. Observe before restore.
            try:
                operation['actual'] = windows_descriptor(path)
            except Exception as read_error:
                operation['readback_error'] = acl_failure(read_error, phase, 'readback')
            raise
        step = operation['step'] = 'readback'
        operation['actual'] = windows_descriptor(path)
        check_fixture_identity(root, record)
        unexpected = {}
        for other in fixture_paths(root):
            observed = windows_descriptor(other)
            wanted = planned if other == path else expected[str(other)]
            if descriptor_contract(observed) != descriptor_contract(wanted):
                unexpected[other.relative_to(root).as_posix()] = observed
        operation['unexpected_objects'] = unexpected
        step = operation['step'] = 'observed'
        operation['observed_sha256'] = operation_snapshot(record, operation, 'observed')
        step = operation['step'] = 'validate'
        check_native_result(operation['native_result'], planned)
        if phase == 'grant':
            check_read_grant(before, operation['actual'], record['sid'], path.is_dir())
        elif record['policy'] == READ_BASELINE_POLICY:
            check_write_deny(before, operation['actual'], record['sid'], directory=path.is_dir())
        if unexpected or descriptor_contract(operation['actual']) != descriptor_contract(planned):
            raise ValueError('actual ordered DACL differs from exact target')
        operation['status'] = 'verified'
        step = operation['step'] = 'receipt'
        operation['verified_sha256'] = operation_snapshot(record, operation, 'verified')
        expected[str(path)] = operation['actual']
    except BaseException as exc:
        if operation['actual'] is None and step in ('write', 'readback'):
            try:
                operation['actual'] = windows_descriptor(path)
            except Exception as read_error:
                operation['readback_error'] = acl_failure(read_error, phase, 'readback')
        operation['status'] = 'failed'
        operation['failure'] = acl_failure(exc, phase, step)
        record['application_failure'] = operation['failure']
        try:
            operation['failure_sha256'] = operation_snapshot(record, operation, 'failure')
        except Exception as persistence:
            operation['failure_persistence_error'] = acl_failure(persistence, phase, 'observed')
        raise


def apply_acl_family(root, record, phase):
    paths = fixture_paths(root)
    check_fixture_identity(root, record)
    expected = dict(record['original_dacls'] if phase == 'grant'
                    else record.get('granted_dacls', record['original_dacls']))
    plans = {}
    # Close the entire input family before the first native write.
    for path in paths:
        before = windows_descriptor(path)
        if descriptor_contract(before) != descriptor_contract(expected[str(path)]):
            raise ValueError('phase DACL differs from frozen snapshot')
        planned = planned_acl_change(before, record['sid'], phase, path.is_dir(), record['policy'])
        plans[str(path)] = (before, planned)
    for path in sorted(paths, key=lambda p: (-len(p.parts), str(p))):
        before, planned = plans[str(path)]
        apply_acl_change(root, record, path, before, planned, phase, expected)
    if inventory(root) != record['original_inventory']:
        raise ValueError('fixture changed during ACL transaction')
    if phase == 'grant':
        record['granted_dacls'] = expected


def prepare_read_transaction(root, *, sid, ownership):
    root = Path(root).absolute()
    required = {'cwd', 'output', 'repo', 'home', 'plugin_root', 'data_root',
                'created_exclusively', 'root_identity'}
    if set(ownership) != required or ownership['created_exclusively'] is not True:
        raise ValueError('exclusive fixture ownership unavailable')
    expected = Path(ownership['cwd']).absolute() / ('incident-readonly-' + Path(ownership['output']).name)
    if root != expected or [root.lstat().st_dev, root.lstat().st_ino] != ownership['root_identity']:
        raise ValueError('fixture creation scope differs')
    output = Path(ownership['output']).resolve(strict=True)
    for key in ('repo', 'home', 'plugin_root', 'data_root', 'output'):
        forbidden = Path(ownership[key]).resolve()
        resolved = root.resolve(strict=True)
        if resolved == forbidden or forbidden in resolved.parents or resolved in forbidden.parents:
            raise ValueError('fixture overlaps protected tree')
    paths = fixture_paths(root)
    if any(p.is_file() and p.lstat().st_nlink != 1 for p in paths):
        raise ValueError('linked fixture file')
    acl_argv(root, sid)
    record = {'family': 'windows-acl', 'policy': READ_BASELINE_POLICY, 'root': str(root),
              'sid': sid, 'collector_sid': current_sid(), 'commands': [], 'operations': [], 'ownership': ownership,
              'operation_output_identity': [output.stat().st_dev, output.stat().st_ino],
              'grant_complete': False, 'deny_complete': False,
              'original_dacls': {str(p): windows_descriptor(p) for p in paths},
              'original_inventory': inventory(root),
              'objects': {str(p): (p.lstat().st_dev, p.lstat().st_ino) for p in paths}}
    record['original_restore_strategies'] = {n: restoration_strategy(d)
                                             for n, d in record['original_dacls'].items()}
    for descriptor in record['original_dacls'].values():
        for ace in descriptor_contract(descriptor)['aces']:
            ace_sid(bytes.fromhex(ace))  # Fail before any ACL mutation on unsupported ACEs.
    for path in paths:
        granted = planned_acl_change(record['original_dacls'][str(path)], sid, 'grant', path.is_dir())
        planned_acl_change(granted, sid, 'deny', path.is_dir())
    snapshot = output / 'fixture-original-transaction.json'
    record['original_snapshot_sha256'] = durable_snapshot(snapshot, record)
    record['original_snapshot_path'] = str(snapshot)
    return record


def verify_original_snapshot(record):
    path = Path(record['original_snapshot_path'])
    output = Path(record.get('operation_output') or record['ownership']['output'])
    if (output.is_symlink()
            or ('operation_output_identity' in record
                and [output.stat().st_dev, output.stat().st_ino] != record['operation_output_identity'])
            or path.absolute() != output.resolve(strict=True) / 'fixture-original-transaction.json'):
        raise ValueError('original snapshot scope changed')
    if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != record['original_snapshot_sha256']:
        raise ValueError('original snapshot changed')
    saved = json.loads(path.read_text())
    fields = ('policy', 'root', 'sid', 'collector_sid', 'original_dacls',
              'original_inventory', 'objects', 'original_restore_strategies')
    fields += ('operation_output',) if 'operation_output' in record else ('ownership',)
    if 'operation_output_identity' in record:
        fields += ('operation_output_identity',)
    if any(saved[k] != json.loads(json.dumps(record[k])) for k in fields):
        raise ValueError('original restore authority changed')


def apply_read_transaction(root, record, phase, *, baseline_record, baseline_request):
    if record.get('policy') != READ_BASELINE_POLICY or phase not in ('grant', 'deny'):
        raise ValueError('unknown fixture transaction phase')
    expected_phase = 'baseline_original' if phase == 'grant' else 'baseline_granted'
    if (baseline_request.get('phase') != expected_phase
            or baseline_request['restriction']['original_snapshot_sha256'] != record['original_snapshot_sha256']
            or baseline_request['restriction']['sid'] != record['sid']
            or (phase == 'grant' and record.get('grant_complete'))
            or (phase == 'deny' and (not record.get('grant_complete') or record.get('deny_complete')))):
        raise ValueError('fixture phase transition differs')
    judge = judge_baseline(baseline_record, baseline_request, require_read=phase == 'deny')
    if judge != ('observed' if phase == 'grant' else 'passed'):
        raise ValueError('required actor baseline failed')
    root = Path(root).absolute()
    verify_original_snapshot(record)
    if record['root'] != str(root) or record['collector_sid'] != current_sid():
        raise ValueError('fixture transaction scope differs')
    step = 'preflight'
    try:
        apply_acl_family(root, record, phase)
        step = 'receipt'
        record[phase + '_complete'] = True
        durable_snapshot(Path(record['ownership']['output']) / ('fixture-' + phase + '-receipt.json'), record)
        return record
    except (Exception, KeyboardInterrupt) as exc:
        record[phase + '_complete'] = False
        record['application_error'] = type(exc).__name__
        record.setdefault('application_failure', acl_failure(exc, phase, step))
        try:
            restore(root, record)
            record['restoration'] = 'verified'
        except Exception as restoration:
            record['restoration_error'] = type(restoration).__name__
        raise RestrictionError(record) from exc


def request_identity_v2(request):
    """v2 only: sorted compact UTF-8 JSON, literal Unicode; CRLF is data.

    Excludes only the outer request_sha256. No Unicode/line normalization.
    v1 retains its historical ASCII-escaped validation and replay domain.
    """
    value = {k: v for k, v in request.items() if k != 'request_sha256'}
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                     allow_nan=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def restored_transaction_observation(root, record):
    """Independent successful readback; leave the existing restoration core intact."""
    verify_original_snapshot(record)
    check_fixture_identity(root, record)
    sid = current_sid()
    if sid != record['collector_sid']:
        raise ValueError('restoration collector changed')
    readback = {str(path): descriptor_contract(windows_descriptor(path)) for path in fixture_paths(root)}
    originals = {name: descriptor_contract(value) for name, value in record['original_dacls'].items()}
    observed = inventory(root)
    if readback != originals or observed != record['original_inventory']:
        raise ValueError('original transaction readback changed')
    return {'status': 'verified', 'original_snapshot_sha256': record['original_snapshot_sha256'],
            'collector_sid': sid, 'descriptor_contracts': readback, 'inventory': observed}


def v2_request(request):
    if (request.get('schema') != 'incident-readonly-request/v2'
            or request.get('restriction', {}).get('policy') != READ_BASELINE_POLICY):
        raise ValueError('unknown v2 readonly request')
    expected = request_identity_v2(request)
    if request.get('request_sha256') != expected:
        raise ValueError('v2 readonly request digest changed')
    return request


def baseline(request):
    v2_request(request)
    # Actor is observed before resolve/stat/list/read can fail.
    sid = current_sid()
    root = Path(request['fixture'])
    checks, observed = {}, None
    def read_files():
        nonlocal observed
        observed = inventory(root)
        return sum(v['kind'] == 'file' for v in observed.values())
    for name, fn in (('resolve', lambda: root.resolve(strict=True)), ('stat', root.stat),
                     ('list', lambda: list(root.iterdir())), ('read_files', read_files)):
        try:
            value = fn()
            checks[name] = {'ok': True}
            if name == 'read_files':
                checks[name]['count'] = value
        except (OSError, ValueError) as exc:
            checks[name] = {'ok': False, 'exception': type(exc).__name__,
                            'errno': getattr(exc, 'errno', None), 'winerror': getattr(exc, 'winerror', None)}
    return {'schema': 'incident-read-baseline/v1', 'request_sha256': request['request_sha256'],
            'sid': sid, 'pid': os.getpid(), 'platform': platform.system(),
            'checks': checks, 'inventory': observed}


def judge_baseline(record, request, *, require_read=True):
    v2_request(request)
    if (set(record) != {'schema', 'request_sha256', 'sid', 'pid', 'platform', 'checks', 'inventory'}
            or record['schema'] != 'incident-read-baseline/v1'
            or record['request_sha256'] != request['request_sha256']
            or record['sid'] != request['restriction']['sid'] or record['platform'] != 'Windows'
            or type(record['pid']) is not int or record['pid'] <= 0
            or set(record['checks']) != {'resolve', 'stat', 'list', 'read_files'}):
        raise ValueError('baseline actor/scope/shape differs')
    for name, value in record['checks'].items():
        if type(value.get('ok')) is not bool:
            raise ValueError('baseline observation unavailable')
        expected = ({'ok', 'count'} if name == 'read_files' else {'ok'}) if value['ok'] else {'ok', 'exception', 'errno', 'winerror'}
        if set(value) != expected:
            raise ValueError('incomplete baseline observation')
        if value['ok'] and name == 'read_files' and (type(value['count']) is not int or value['count'] < 0):
            raise ValueError('invalid baseline file count')
        if not value['ok'] and (not isinstance(value['exception'], str) or not value['exception']
                               or any(value[k] is not None and type(value[k]) is not int for k in ('errno', 'winerror'))):
            raise ValueError('invalid baseline read failure')
    if not require_read:
        return 'observed'  # A failed original baseline is retained, never called a read pass.
    expected_count = sum(v['kind'] == 'file' for v in request['inventory'].values())
    return 'passed' if (all(v['ok'] for v in record['checks'].values())
                        and record['checks']['read_files']['count'] == expected_count
                        and record['inventory'] == request['inventory']) else 'failed'


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
    for path in paths:
        planned_acl_change(record['original_dacls'][str(path)], sid, 'deny', path.is_dir(), record['policy'])
    record['operation_output'] = str(Path(tempfile.mkdtemp(prefix='cg-acl-private-operation-')).resolve(strict=True))
    output = Path(record['operation_output'])
    record['operation_output_identity'] = [output.stat().st_dev, output.stat().st_ino]
    snapshot = Path(record['operation_output']) / 'fixture-original-transaction.json'
    record['original_snapshot_sha256'] = durable_snapshot(snapshot, record)
    record['original_snapshot_path'] = str(snapshot)
    # All unsupported controls/NULL shapes reject before any ACL command.
    try:
        apply_acl_family(root, record, 'deny')
        return record
    except (Exception, KeyboardInterrupt) as exc:
        record['application_error'] = type(exc).__name__
        record.setdefault('application_failure', acl_failure(exc, 'deny', 'preflight'))
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
        if (record.get('policy') not in ('specific-write-deny/v2', READ_BASELINE_POLICY)
                or record.get('root') != str(root) or record.get('collector_sid') != current_sid()
                or set(record.get('original_dacls', {})) != {str(p) for p in paths}):
            raise ValueError('restoration scope or principal differs')
        if record.get('policy') == READ_BASELINE_POLICY or 'original_snapshot_path' in record:
            verify_original_snapshot(record)
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
    if request.get('schema') == 'incident-readonly-request/v2':
        v2_request(request)
        observed = baseline(request)
        if judge_baseline(observed, request) != 'passed':
            return {'schema': 'incident-readonly-child/v2', 'request_sha256': request['request_sha256'],
                    'sid': observed['sid'], 'pid': observed['pid'], 'ppid': os.getppid(),
                    'platform': observed['platform'], 'baseline': observed, 'write_attempts': [],
                    'before': observed['inventory'], 'after': observed['inventory'],
                    'cli_exit_code': None, 'query_stdout': '', 'query_stderr': ''}
        legacy = dict(request, schema='incident-readonly-request/v1')
        try:
            value = witness(legacy)
        except (OSError, ValueError) as exc:
            return {'schema': 'incident-readonly-child/v2', 'request_sha256': request['request_sha256'],
                    'sid': observed['sid'], 'pid': observed['pid'], 'ppid': os.getppid(),
                    'platform': observed['platform'], 'baseline': observed, 'write_attempts': [],
                    'before': observed['inventory'], 'after': None, 'cli_exit_code': None,
                    'query_stdout': '', 'query_stderr': '',
                    'operation_failure': {'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None),
                                          'winerror': getattr(exc, 'winerror', None)}}
        value.update(schema='incident-readonly-child/v2', baseline=observed)
        return value
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
    if request.get('schema') == 'incident-readonly-request/v2':
        v2_request(request)
        if (record.get('schema') != 'incident-readonly-child/v2'
                or record.get('request_sha256') != request['request_sha256']):
            raise ValueError('wrong v2 child schema')
        if record.get('operation_failure') or judge_baseline(record.get('baseline', {}), request) != 'passed':
            return 'failed'
        if not all(request['restriction'].get(k) is True for k in ('grant_complete', 'deny_complete')):
            raise ValueError('incomplete readonly transaction')
        legacy_record = {k: v for k, v in record.items() if k != 'baseline'}
        legacy_record['schema'] = SCHEMA
        legacy_request = dict(request, schema='incident-readonly-request/v1')
        legacy_request['request_sha256'] = hashlib.sha256(json.dumps(
            {k: v for k, v in legacy_request.items() if k != 'request_sha256'},
            ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        legacy_record['request_sha256'] = legacy_request['request_sha256']
        return judge(legacy_record, legacy_request)
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
    p.add_argument('--baseline', action='store_true')
    a = p.parse_args()
    if a.baseline and not a.request:
        p.error('--baseline requires --request')
    if a.identity:
        if os.name != 'nt':
            raise ValueError('Windows tool principal required')
        print(json.dumps({'schema': 'incident-child-principal/v1', 'sid': current_sid(),
                          'pid': os.getpid(), 'platform': platform.system()}))
        return 0
    request = json.loads(a.request.read_text())
    if a.baseline:
        value = baseline(request)
        print(json.dumps(value, ensure_ascii=True))
        return 0
    value = witness(request)
    print(json.dumps(value, ensure_ascii=True))
    return 0 if judge(value, request) == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
