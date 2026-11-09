"""Bounded Windows retention filesystem acceptance; no login/install.

Only synthetic fixtures are changed. Verification validates recorded observations,
not provenance of arbitrary supplied JSON. Run only after a reviewed toolkit commit.
The caller supplies the frozen product commit and runtime-tree digest. The
toolkit may live in the same committed checkout as the product.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import errno
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path, PureWindowsPath

SCHEMA = "cg-windows-retention-native/v2"
CASES = ("dacl_refusal", "no_delete_share", "case_alias", "long_payload")
FIELDS = (
    "requirements",
    "acceptance_items",
    "work_units",
    "open_items",
    "wait_conditions",
)
DEPS = (
    "tools/validation/windows_retention_native.py",
    "tools/validation/incident_readonly_child.py",
)


class Unavailable(RuntimeError):
    """A real setup capability was unavailable; never a passed scenario."""


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def reject(_value):
        raise ValueError("non-finite JSON")

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number

    return json.loads(
        text, object_pairs_hook=pairs, parse_constant=reject, parse_float=finite
    )


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("module unavailable")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def plain(path, *, absent=False):
    """Inspect lexical ancestors BEFORE resolution or any write."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute non-traversing paths required")
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if absent and part == path:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked/reparse path refused")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("multiply linked file refused")
    return path


def within(path, root):
    # normcase handles Windows aliases without changing the strings passed to cg.
    p, r = os.path.normcase(str(path)), os.path.normcase(str(root))
    return os.path.commonpath((p, r)) == r


def disjoint(a, b):
    try:
        return not within(a, b) and not within(b, a)
    except ValueError:  # different volumes
        return True


def check_destinations(output, fixture, private_parent, protected):
    output, fixture, parent = (
        plain(output, absent=True),
        plain(fixture, absent=True),
        plain(private_parent),
    )
    if not parent.is_dir() or not output.parent.is_dir():
        raise ValueError("existing private parents required")
    if output.exists() or fixture.exists():
        raise ValueError("new exclusive output and fixture paths required")
    if fixture.parent != parent or not within(output.parent, parent):
        raise ValueError("fixture must be direct child; result under private parent")
    if not disjoint(output, fixture):
        raise ValueError("results must be outside fixture")
    sidecar = output.with_suffix(".events.jsonl")
    if not disjoint(sidecar, fixture):
        raise ValueError("event output overlaps fixture")
    for target in (output, sidecar, fixture):
        for root in protected:
            if not disjoint(target, plain(root)):
                raise ValueError("destination overlaps protected root")
    if output.with_suffix(".events.jsonl").exists():
        raise ValueError("event output already exists")


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=True, timeout=30
    ).stdout


def compare_installed_without_extra_reads(identity, installed, manifest):
    """Names/metadata first; never read/hash any unexpected file, including auth."""
    files = {
        p.relative_to(installed).as_posix()
        for p, info in identity.checked_walk(installed)
        if not stat.S_ISDIR(info.st_mode)
    }
    if files != set(manifest) or any(
        Path(p).name.casefold() == "auth.json" for p in files
    ):
        raise ValueError("installed file set differs; no extra content read")
    for relative, expected in manifest.items():
        if file_digest(identity.safe_file(installed, relative)) != expected:
            raise ValueError("installed expected file bytes differ")


def bindings(args):
    source = args.source_commit
    runtime = args.runtime_tree_sha256
    if not re.fullmatch("[0-9a-f]{40}", source):
        raise ValueError("full product commit required")
    if not re.fullmatch("[0-9a-f]{64}", runtime):
        raise ValueError("full runtime-tree SHA-256 required")
    tool, product, installed, archive = map(
        plain,
        (
            args.tool_repo_root,
            args.product_repo_root,
            args.installed_plugin_root,
            args.release_zip,
        ),
    )
    if not re.fullmatch("[0-9a-f]{40}", args.tool_commit):
        raise ValueError("full toolkit commit required")
    if git(tool, "rev-parse", "HEAD").decode().strip() != args.tool_commit:
        raise ValueError("toolkit HEAD differs")
    if git(tool, "status", "--porcelain").strip():
        raise ValueError("toolkit checkout is dirty")
    if Path(__file__).absolute() != tool / DEPS[0]:
        raise ValueError("execute the committed toolkit module itself")
    dependencies = {}
    for rel in DEPS:
        data = plain(tool / rel).read_bytes()
        if git(tool, "show", args.tool_commit + ":" + rel) != data:
            raise ValueError("toolkit dependency disk bytes differ")
        dependencies[rel] = hashlib.sha256(data).hexdigest()
    protected_homes = [plain(Path.home() / ".codex"), *map(plain, args.protected_root)]
    for home in protected_homes:
        if within(home, installed) or not disjoint(archive, home):
            raise ValueError("installation contains a HOME or ZIP overlaps a HOME")
    if archive.name.casefold() == "auth.json":
        raise ValueError("credential file is never a ZIP input")
    backend = load(tool / DEPS[1], "windows_retention_binding_backend")
    # Resolve aliases with metadata handles BEFORE content hashing below.
    for path in (tool, product, installed, archive, *protected_homes):
        api, handle = pin_canonical(backend, path)
        if backend.close_windows_handle(api, handle)["return_value"] != 1:
            raise ValueError("binding handle close failed")
    if git(product, "rev-parse", "HEAD").decode().strip() != source:
        raise ValueError("product source is not the frozen commit")
    if git(product, "status", "--porcelain").strip():
        raise ValueError("product checkout is dirty")
    identity_path = product / "scripts/artifact_identity.py"
    if (
        git(product, "show", source + ":scripts/artifact_identity.py")
        != identity_path.read_bytes()
    ):
        raise ValueError("artifact identity helper differs")
    identity = load(identity_path, "windows_retention_identity")
    for area in identity.RUNTIME_ROOTS:
        directory = product / area
        if directory.exists() and any(
            p.name.casefold() == "auth.json"
            for p, _info in identity.checked_walk(directory, ignore_runtime=True)
        ):
            raise ValueError("credential-named source input refused before hashing")
    if digest(identity.tree_manifest(product)) != runtime:
        raise ValueError("source runtime differs")
    manifest = identity.distribution_manifest(product)
    if not disjoint(installed, product) or not disjoint(installed, tool):
        raise ValueError("installation must be separate from source/tool checkouts")
    # Refuse a HOME passed as installation before any recursive walk.
    plain(installed / ".codex-plugin/plugin.json")
    plain(installed / ".codex-plugin/distribution-manifest.json")
    compare_installed_without_extra_reads(identity, installed, manifest)
    actual_zip = validate_archive(archive, manifest, args.release_zip_sha256)
    subject = {
        "tool_commit": args.tool_commit,
        "tool_dependencies": dependencies,
        "product_commit": source,
        "runtime_tree_sha256": runtime,
        "artifact_identity_sha256": file_digest(identity_path),
        "release_zip_sha256": actual_zip,
        "release_zip_size": archive.stat().st_size,
        "installed_plugin_root": str(installed),
        "distribution_sha256": digest(manifest),
        "fixture_root": str(args.fixture_root),
        "python": {
            "path": sys.executable,
            "version": list(sys.version_info[:3]),
            "sha256": file_digest(Path(sys.executable)),
        },
    }
    return subject, installed, tool


def validate_archive(archive, manifest, expected_sha256):
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if (
            len(names) != len(manifest)
            or set(names) != set(manifest)
            or any(PureWindowsPath(n).name.casefold() == "auth.json" for n in names)
        ):
            raise ValueError(
                "ZIP file set differs; no payload or whole-archive digest read"
            )
        actual = file_digest(archive)
        if (
            not re.fullmatch("[0-9a-f]{64}", expected_sha256)
            or actual != expected_sha256
        ):
            raise ValueError("canonical ZIP SHA differs")
        if any(hashlib.sha256(z.read(n)).hexdigest() != h for n, h in manifest.items()):
            raise ValueError("ZIP bytes differ")
    return actual


def _classify_private_dacl(text, sid):
    """Classify private-DACL ACE trustees into user/system/other roles.

    Only the exact current-user SID string is "user"; SYSTEM is "system".
    Every other trustee — OWNER RIGHTS (``S-1-3-4``), group SIDs, architecture
    aliases or any extra principal — is "other", and the caller refuses any
    role set other than exactly one "user" plus one "system". The classification
    is pure so the OWNER-RIGHTS/explicit-SID distinction stays regression-pinned
    on platforms without the Windows ACL APIs.
    """
    entries = re.findall(r"\(([^()]+)\)", text)
    roles = []
    for ace in entries:
        parts = ace.split(";")
        if len(parts) != 6:
            raise Unavailable("unsupported private ACE")
        kind, flags, rights, obj, inherited, trustee = parts
        if kind != "A" or obj or inherited or rights not in ("FA", "0x1f01ff"):
            raise Unavailable("private full-control ACE required")
        if flags not in ("", "OICI", "OICIID", "ID", "CI", "CIID", "OI", "OIID"):
            raise Unavailable("unsupported inheritance flags")
        roles.append(
            "user"
            if trustee == sid
            else "system"
            if trustee in ("SY", "S-1-5-18")
            else "other"
        )
    return entries, roles


def private_acl(cg, path):
    """Conservative allow-list; unsupported ACL shapes fail preflight."""
    text = cg._windows_query_dacl_sddl(path)
    if not isinstance(text, str) or not re.fullmatch(r"D:[A-Z]*(?:\([^()]+\))+", text):
        raise Unavailable("private DACL cannot be established")
    sid = cg._windows_current_user_sid()
    from ctypes import wintypes

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    owner, sd = ctypes.c_void_p(), ctypes.c_void_p()
    query = api.GetNamedSecurityInfoW
    query.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    query.restype = ctypes.c_uint32
    convert = api.ConvertSidToStringSidW
    convert.argtypes, convert.restype = (
        [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)],
        wintypes.BOOL,
    )
    free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
    text_owner = wintypes.LPWSTR()
    error = query(
        str(path), 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(sd)
    )
    try:
        if (
            error
            or not convert(owner, ctypes.byref(text_owner))
            or text_owner.value != sid
        ):
            raise Unavailable("private parent owner is not provably current user")
    finally:
        if text_owner:
            free(ctypes.cast(text_owner, ctypes.c_void_p))
        if sd:
            free(sd)
    entries, roles = _classify_private_dacl(text, sid)
    if sorted(roles) != ["system", "user"]:
        raise Unavailable("private parent must allow current user and SYSTEM only")
    return {
        "owner_current": True,
        "current_user_system_only": True,
        "ace_count": len(entries),
    }


def pin_canonical(backend, path):
    """Reject SUBST/8.3/device aliases; hold directory against replacement."""
    api, handle = backend.open_windows_handle(path, 0x20080)
    try:
        from ctypes import wintypes

        query = api.GetFinalPathNameByHandleW
        query.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        query.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        count = query(handle, buffer, len(buffer), 0)
        if not 0 < count < len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        final = buffer.value
        if final.startswith("\\\\?\\"):
            final = final[4:]
        if os.path.normcase(final.rstrip("\\")) != os.path.normcase(
            str(path).rstrip("\\")
        ):
            raise Unavailable("unproven physical path alias; use ordinary final path")
        return api, handle
    except BaseException:
        backend.close_windows_handle(api, handle)
        raise


def set_handle_dacl(backend, handle, descriptor, *, restore=False):
    """Set ONLY DACL on the already pinned file, never a replacement path."""
    from ctypes import wintypes

    raw = base64.b64decode(descriptor, validate=True)
    contract = backend.descriptor_contract(descriptor)
    buffer = ctypes.create_string_buffer(raw)
    offset = struct.unpack_from("<I", raw, 16)[0]
    acl = ctypes.c_void_p(ctypes.addressof(buffer) + offset)
    flags = 4
    if restore:
        flags |= 0x80000000 if contract["dacl_control"] & 0x1000 else 0x20000000
    write = ctypes.WinDLL("advapi32", use_last_error=True).SetSecurityInfo
    write.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    write.restype = ctypes.c_uint32
    error = write(handle, 1, flags, None, None, acl, None)
    if error:
        raise ctypes.WinError(error)
    return {"api": "SetSecurityInfo_DACL_only", "winerror": 0, "flags": flags}


def private_mkdir(cg, path):
    path.mkdir(exist_ok=False)
    sid = cg._windows_current_user_sid()
    cg._windows_apply_protected_dacl(path, f"D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
    return private_acl(cg, path)


def snapshot(cg, home, payload=None):
    info = home.lstat()
    stamp = cg._retention_object_stamp(home, info)
    if not stamp or stamp.get("kind") != "birth":
        raise Unavailable("strong creation identity unavailable")
    state = (
        cg.load_state(home, payload)
        if payload
        else strict_json((home / "state.json").read_text(encoding="utf-8"))
    )
    cg.validate_state_integrity(state)
    return {
        "dev": info.st_dev,
        "ino": info.st_ino,
        "birth_ns": stamp["ns"],
        "session_id": state["session"]["id"],
        "ledger_sha256": digest({k: state.get(k) for k in FIELDS}),
        "state_sha256": file_digest(home / "state.json"),
    }


def same_snapshot(a, b):
    keys = ("dev", "ino", "birth_ns", "session_id", "ledger_sha256", "state_sha256")
    return (
        isinstance(a, dict)
        and isinstance(b, dict)
        and all(k in a and a[k] == b.get(k) for k in keys)
    )


def delete_access_probe(path):
    """Non-mutating DELETE-access open; proves real sharing error 32."""
    from ctypes import wintypes

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    create = api.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    handle = create(str(path), 0x10000, 7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        return {"api": "CreateFileW_DELETE", "winerror": ctypes.get_last_error()}
    close = api.CloseHandle
    close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
    if not close(handle):
        raise ctypes.WinError(ctypes.get_last_error())
    return {"api": "CreateFileW_DELETE", "winerror": 0}


def read_access_probe(path):
    """Request FILE_READ_DATA independently of Python's CRT error mapping."""
    from ctypes import wintypes

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    create = api.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    observation = {
        "api": "CreateFileW_FILE_READ_DATA",
        "desired_access": 1,
        "share_mode": 7,
        "creation_disposition": 3,
        "flags": 0x00200000,
    }
    handle = create(str(path), 1, 7, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        # Capture GetLastError immediately, before another native call.
        observation.update(opened=False, winerror=ctypes.get_last_error())
        return observation
    observation.update(opened=True, winerror=0)
    closed = None
    try:
        close = api.CloseHandle
        close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
        closed = int(close(handle))
        observation["close"] = {
            "api": "CloseHandle",
            "return_value": closed,
            "winerror": 0 if closed else ctypes.get_last_error(),
        }
    except Exception as exc:
        observation["close"] = {
            "api": "CloseHandle",
            "return_value": closed,
            "winerror": None,
            "error": {
                "type": type(exc).__name__,
                "errno": getattr(exc, "errno", None),
                "winerror": getattr(exc, "winerror", None),
            },
        }
    return observation


def python_read_probe(path):
    """Keep the actual Python exception; never manufacture a Win32 code."""
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except OSError as exc:
        return {
            "outcome": "error",
            "type": type(exc).__name__,
            "errno": exc.errno,
            "winerror": getattr(exc, "winerror", None),
        }
    return {"outcome": "read", "type": None, "errno": None, "winerror": None}


def dacl_reads_denied(native, python):
    """Both independent observations are required, with exact numeric types."""
    expected = {
        "api": "CreateFileW_FILE_READ_DATA",
        "desired_access": 1,
        "share_mode": 7,
        "creation_disposition": 3,
        "flags": 0x00200000,
        "opened": False,
        "winerror": 5,
    }
    return (
        isinstance(native, dict)
        and set(native) == set(expected)
        and all(
            type(native[k]) is type(v) and native[k] == v for k, v in expected.items()
        )
        and isinstance(python, dict)
        and set(python) == {"outcome", "type", "errno", "winerror"}
        and python["outcome"] == "error"
        and python["type"] == "PermissionError"
        and type(python["errno"]) is int
        and python["errno"] == errno.EACCES
        and (
            python["winerror"] is None
            or (type(python["winerror"]) is int and python["winerror"] == 5)
        )
    )


class Fixture:
    def __init__(self, cg, backend, work, emit):
        self.cg, self.backend, self.work, self.emit = cg, backend, work, emit
        self.data = work / "data"
        self.payload_root = work / "project"
        self.payload_root.mkdir()
        self.guard = self.make("unfinished-guard", finished=False)
        cg.write_retention_policy(self.data, enabled=True, quarantine_days=7)
        self.guard_before = snapshot(cg, self.guard)
        if not cg._retention_has_unfinished_work(
            strict_json((self.guard / "state.json").read_text(encoding="utf-8"))
        ):
            raise AssertionError("guard fixture has no unfinished work")

    def payload(self, name):
        return {
            "hook_event_name": "SessionStart",
            "session_id": name,
            "cwd": str(self.payload_root),
            "turn_id": "windows-edge",
        }

    def make(self, name, *, finished=True):
        p = self.payload(name)
        self.cg.dispatch(
            dict(
                p,
                hook_event_name="UserPromptSubmit",
                prompt="Verify the synthetic acceptance marker.",
            )
        )
        home = self.data / self.cg.V2_NAMESPACE / self.cg.safe_session_id(name)
        self.finish(home, finished)
        return home

    def finish(self, home, finished=True):
        path = home / "state.json"
        state = strict_json(path.read_text(encoding="utf-8"))
        if finished:
            for group in ("requirements", "acceptance_items"):
                for item in state.get(group, []):
                    item["status"] = "pass"
            for unit in state.get("work_units", []):
                unit.update(status="completed", closed_at=self.cg.utc_now())
            state.update(open_items=[], wait_conditions=[])
        state["session"]["ended_at"] = (
            self.cg.dt.datetime.now(self.cg.dt.timezone.utc)
            - self.cg.dt.timedelta(days=45)
        ).isoformat()
        state["content_hash"] = self.cg.state_content_hash(state)
        path.write_text(
            json.dumps(state, ensure_ascii=False), encoding="utf-8", newline=""
        )

    def reader(self, home):
        return snapshot(self.cg, home, self.payload(home.name))

    def run(self, data=None):
        r = self.cg.cleanup_old_sessions(
            data or self.data, apply=True, deadline=time.monotonic() + 20
        )
        self.emit({"kind": "retention_report", "report": r})
        return r

    def advance(self, home, reference, data=None, payload_relative=None):
        cg = self.cg
        report = self.run(data)
        qdir = cg._retention_quarantine_dir(self.data)
        rows = [
            (p, r)
            for p, r in cg._retention_iter_records(qdir)
            if r["original_name"] == home.name
        ]
        if len(rows) != 1 or home.exists():
            raise AssertionError(
                "positive quarantine did not move exactly one bound object"
            )
        record = rows[0][1]
        bound = {
            "identity": record["identity"],
            "object_stamp": record.get("object_stamp"),
            "original_name": record["original_name"],
        }
        restored = cg.retention_restore(
            self.data, home.name, deadline=time.monotonic() + 20
        )
        readback = self.reader(home)
        if restored.get("outcome") != "restored" or not same_snapshot(
            reference, readback
        ):
            raise AssertionError(
                "positive restore did not preserve the original ledger"
            )
        payload_readback = (
            file_digest(home / payload_relative) if payload_relative else None
        )
        self.run(data)
        rows = [
            (p, r)
            for p, r in cg._retention_iter_records(qdir)
            if r["original_name"] == home.name
        ]
        if len(rows) != 1:
            raise AssertionError("second quarantine missing")
        p, record = rows[0]
        target = qdir / record["quarantine_object"]
        # Explicit synthetic adjudication time, NOT an OS/datetime mock.
        future = cg.dt.datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=8)
        with cg._retention_maintenance_lock(self.data, deadline=time.monotonic() + 20):
            purge = cg._retention_purge_pass(
                self.data,
                cg.read_retention_policy(self.data),
                future,
                time.monotonic() + 20,
            )
        self.emit({"kind": "positive_purge_report", "report": purge})
        return {
            "quarantine_report": report,
            "record_binding": bound,
            "restore_outcome": restored.get("outcome"),
            "reader": readback,
            "payload_readback_sha256": payload_readback,
            "purge_report": purge,
            "target_absent": not target.exists(),
            "record_absent": not p.exists(),
            "tombstone_exists": (
                qdir / (record["quarantine_object"] + ".tombstone.json")
            ).is_file(),
        }


def scenario(name, f):
    cg, backend = f.cg, f.backend
    home = f.make("candidate", finished=name != "long_payload")
    before = snapshot(cg, home)
    row = {
        "name": name,
        "status": "running",
        "before": before,
        "guard_before": f.guard_before,
        "resources": {"dacl_restored": True, "handles_closed": True},
    }
    condition = {}
    try:
        if name == "dacl_refusal":
            target = home / "state.json"
            try:
                api, handle = backend.open_windows_handle(target, 0x60080)
            except OSError as exc:
                raise Unavailable(
                    "DACL recovery handle unavailable; winerror="
                    + str(getattr(exc, "winerror", None))
                ) from exc
            row["resources"]["handles_closed"] = False
            saved, pinned_identity = None, None
            read_probe_closed = True
            try:
                pinned_identity = backend.windows_handle_identity(api, handle)
                saved = backend.windows_handle_descriptor(handle)
                condition["pinned_before"] = pinned_identity
                condition["original_dacl_sha256"] = digest(
                    backend.descriptor_contract(saved)
                )
                backend.restoration_strategy(saved)
                recovery = f.work / "original-dacl.json"
                with recovery.open("x", encoding="utf-8", newline="") as stream:
                    private_acl(cg, recovery)
                    json.dump(
                        {
                            "relative": str(target.relative_to(f.work)),
                            "descriptor": saved,
                        },
                        stream,
                    )
                sid = cg._windows_current_user_sid()
                deny_sid = backend.sid_bytes(sid)
                ace = struct.pack("<BBHI", 1, 0, 8 + len(deny_sid), 1) + deny_sid
                aces = [ace.hex(), *backend.descriptor_contract(saved)["aces"]]
                denied = backend.descriptor_with_aces(saved, aces)
                try:
                    condition["apply_api"] = set_handle_dacl(backend, handle, denied)
                except OSError as exc:
                    raise Unavailable(
                        "DACL setup unavailable; winerror="
                        + str(getattr(exc, "winerror", None))
                    ) from exc
                row["resources"]["dacl_restored"] = False
                condition["dacl_changed"] = backend.descriptor_contract(
                    backend.windows_handle_descriptor(handle)
                ) != backend.descriptor_contract(saved)
                condition["read_path_before"] = backend.windows_object_identity(target)
                condition["native_read_probe"] = read_access_probe(target)
                if condition["native_read_probe"].get("opened") is True:
                    read_probe_closed = (
                        condition["native_read_probe"]["close"]["return_value"] == 1
                    )
                condition["python_read_probe"] = python_read_probe(target)
                condition["read_path_after"] = backend.windows_object_identity(target)
                if any(
                    condition[key] != pinned_identity
                    for key in ("read_path_before", "read_path_after")
                ):
                    raise AssertionError("DACL read probe file identity differs")
                if condition["dacl_changed"] is not True or not dacl_reads_denied(
                    condition["native_read_probe"], condition["python_read_probe"]
                ):
                    raise AssertionError(
                        "independent native/Python read denials missing"
                    )
                condition["report"] = f.run()
            except BaseException as exc:
                condition["primary_error"] = {
                    "type": type(exc).__name__,
                    "errno": getattr(exc, "errno", None),
                    "winerror": getattr(exc, "winerror", None),
                    "message": str(exc),
                }
                raise
            finally:
                try:
                    if saved is not None:
                        if (
                            backend.windows_handle_identity(api, handle)
                            != pinned_identity
                        ):
                            raise AssertionError("pinned DACL object changed")
                        condition["restore_api"] = set_handle_dacl(
                            backend, handle, saved, restore=True
                        )
                        condition["pinned_after"] = backend.windows_handle_identity(
                            api, handle
                        )
                        condition["path_after"] = backend.windows_object_identity(
                            target
                        )
                        if any(
                            condition[key] != pinned_identity
                            for key in ("pinned_after", "path_after")
                        ):
                            raise AssertionError("DACL restored file identity differs")
                        condition["restored_dacl_sha256"] = digest(
                            backend.descriptor_contract(
                                backend.windows_handle_descriptor(handle)
                            )
                        )
                        condition["restored_state_sha256"] = file_digest(target)
                        if condition["restored_state_sha256"] != before["state_sha256"]:
                            raise AssertionError("DACL restored file content differs")
                        row["resources"]["dacl_restored"] = backend.descriptor_contract(
                            backend.windows_handle_descriptor(handle)
                        ) == backend.descriptor_contract(saved)
                        if not row["resources"]["dacl_restored"]:
                            raise AssertionError("original DACL restoration differs")
                except BaseException as exc:
                    condition["cleanup_error"] = {
                        "type": type(exc).__name__,
                        "errno": getattr(exc, "errno", None),
                        "winerror": getattr(exc, "winerror", None),
                        "message": str(exc),
                    }
                    row["resources"]["dacl_restored"] = False
                    raise
                finally:
                    condition["close"] = backend.close_windows_handle(api, handle)
                    row["resources"]["handles_closed"] = (
                        read_probe_closed and condition["close"]["return_value"] == 1
                    )
                    if not row["resources"]["handles_closed"]:
                        raise AssertionError("DACL recovery handle close failed")
        elif name == "no_delete_share":
            try:
                # FILE_LIST_DIRECTORY makes the open participate in sharing checks.
                api, handle = backend.open_windows_handle(home, 0x20081)
            except OSError as exc:
                raise Unavailable(
                    "no-delete handle setup unavailable; winerror="
                    + str(getattr(exc, "winerror", None))
                ) from exc
            row["resources"]["handles_closed"] = False
            try:
                condition["share_mode"] = 3
                condition["handle_identity"] = backend.windows_handle_identity(
                    api, handle
                )
                condition["path_identity"] = backend.windows_object_identity(home)
                condition["delete_probe"] = delete_access_probe(home)
                if condition["delete_probe"]["winerror"] != 32:
                    raise AssertionError(
                        "actual DELETE open did not report sharing violation"
                    )
                condition["report"] = f.run()
            except BaseException as exc:
                condition["primary_error"] = {
                    "type": type(exc).__name__,
                    "winerror": getattr(exc, "winerror", None),
                    "message": str(exc),
                }
                raise
            finally:
                condition["close"] = backend.close_windows_handle(api, handle)
                row["resources"]["handles_closed"] = (
                    condition["close"]["return_value"] == 1
                )
                if not row["resources"]["handles_closed"]:
                    raise AssertionError("CloseHandle failed")
        elif name == "case_alias":
            alias = str(f.data.parent / f.data.name.upper())
            if (
                alias == str(f.data)
                or not Path(alias).exists()
                or not os.path.samefile(alias, f.data)
            ):
                raise Unavailable("case alias does not name the same root")
            condition.update(
                original=str(f.data),
                alias=alias,
                original_identity=backend.windows_object_identity(f.data),
                alias_identity=backend.windows_object_identity(Path(alias)),
            )
            import msvcrt

            with cg.lifecycle_lock_path(home).open("a+b") as lock:
                if lock.seek(0, 2) == 0:
                    lock.write(b"0")
                    lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    condition["report"] = f.run(
                        Path(alias)
                    )  # preserve actual alias spelling
                finally:
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            condition["kernel_lock_released"] = True
        else:
            if not cg._retention_has_unfinished_work(
                strict_json((home / "state.json").read_text(encoding="utf-8"))
            ):
                raise AssertionError(
                    "long-path negative fixture has no unfinished work"
                )
            payload = home
            while len(str(payload / "payload.bin")) <= 300:
                payload = payload / ("segment-" + "x" * 40)
            try:
                payload.mkdir(parents=True, exist_ok=False)
                payload = payload / "payload.bin"
                payload.write_bytes(b"synthetic long-path sentinel")
            except OSError as exc:
                raise Unavailable(
                    "ordinary long-path setup unavailable; winerror="
                    + str(getattr(exc, "winerror", None))
                ) from exc
            condition.update(
                path_form="ordinary_absolute",
                path_chars=len(str(payload)),
                payload_path=str(payload),
                max_component_chars=max(map(len, payload.parts)),
                payload_sha256=file_digest(payload),
            )
            condition["report"] = f.run()  # unfinished candidate must stay protected
        row["condition"] = condition
        row["protected_reader"] = f.reader(home)
        if not same_snapshot(before, row["protected_reader"]):
            raise AssertionError("protected reader differs from original object/ledger")
        if name == "long_payload":
            condition["protected_payload_sha256"] = file_digest(payload)
            f.finish(home)  # explicit synthetic completion; bind new positive reference
            condition["synthetic_completion"] = True
        row["positive_reference"] = snapshot(cg, home)
        row["positive"] = f.advance(
            home,
            row["positive_reference"],
            Path(condition["alias"]) if name == "case_alias" else None,
            payload.relative_to(home) if name == "long_payload" else None,
        )
        if name == "long_payload":
            row["condition"]["payload_absent_after_purge"] = not payload.exists()
        row["guard_reader"] = f.reader(f.guard)
        row["status"] = "passed"
    except Unavailable as exc:
        clean = all(v is True for v in row["resources"].values())
        row.update(
            status="capability_unavailable" if clean else "failed",
            reason=str(exc),
            condition=condition,
        )
    except Exception as exc:
        row.update(
            status="failed",
            error={
                "type": type(exc).__name__,
                "winerror": getattr(exc, "winerror", None),
                "errno": getattr(exc, "errno", None),
                "message": str(exc),
            },
            condition=condition,
        )
    return row


def verify_result(result, expected):
    """Closed consumer: recompute from facts, never trust a passed/checks flag."""
    errors = []
    if not isinstance(result, dict):
        return ["result"]
    if result.get("schema") != SCHEMA or result.get("binding") != expected:
        errors.append("schema_or_binding")
    if result.get("fixture_root") != expected.get("fixture_root"):
        errors.append("fixture_binding")
    if result.get("binding_unchanged_after_execution") is not True:
        errors.append("post_execution_binding")
    rows = result.get("cases")
    if not isinstance(rows, list) or len(rows) != len(CASES):
        return errors + ["case_set"]
    names = [r.get("name") if isinstance(r, dict) else None for r in rows]
    if len(set(n for n in names if isinstance(n, str))) != 4 or set(
        n for n in names if isinstance(n, str)
    ) != set(CASES):
        errors.append("case_set")
    for r in rows:
        if not isinstance(r, dict):
            errors.append("case_row")
            continue
        name = r.get("name")
        try:
            if r["status"] != "passed":
                raise ValueError("nonpassing capability or case")
            for key in (
                "before",
                "protected_reader",
                "positive_reference",
                "guard_before",
                "guard_reader",
            ):
                v = r[key]
                if any(
                    type(v[k]) is not int or v[k] <= 0
                    for k in ("dev", "ino", "birth_ns")
                ):
                    raise ValueError("identity")
                if (
                    not isinstance(v["session_id"], str)
                    or not v["session_id"]
                    or not all(
                        isinstance(v[k], str) and re.fullmatch("[0-9a-f]{64}", v[k])
                        for k in ("ledger_sha256", "state_sha256")
                    )
                ):
                    raise ValueError("reader hashes")
            if not same_snapshot(
                r["before"], r["protected_reader"]
            ) or not same_snapshot(r["guard_before"], r["guard_reader"]):
                raise ValueError("protected object")
            if set(r["resources"]) != {"dacl_restored", "handles_closed"} or any(
                v is not True for v in r["resources"].values()
            ):
                raise ValueError("resource cleanup")
            p, ref, c = r["positive"], r["positive_reference"], r["condition"]
            if any(
                r["before"][k] != ref[k]
                for k in ("dev", "ino", "birth_ns", "session_id")
            ):
                raise ValueError("positive object was replaced")
            if name != "long_payload" and not same_snapshot(r["before"], ref):
                raise ValueError("positive ledger changed")
            if name == "long_payload" and c["synthetic_completion"] is not True:
                raise ValueError("synthetic completion missing")
            if (
                not same_snapshot(ref, p["reader"])
                or p["restore_outcome"] != "restored"
            ):
                raise ValueError("positive reader")
            if any(type(p["reader"][k]) is not int for k in ("dev", "ino", "birth_ns")):
                raise ValueError("positive reader identity types")
            if (
                any(type(v) is not int for v in p["record_binding"]["identity"])
                or type(p["record_binding"]["object_stamp"]["ns"]) is not int
            ):
                raise ValueError("record identity types")
            if p["record_binding"] != {
                "identity": [ref["dev"], ref["ino"]],
                "object_stamp": {"kind": "birth", "ns": ref["birth_ns"]},
                "original_name": ref["session_id"],
            }:
                raise ValueError("positive strong binding")
            if any(
                p[k] is not True
                for k in ("target_absent", "record_absent", "tombstone_exists")
            ):
                raise ValueError("positive purge objects")
            if (
                type(p["purge_report"]["purged"]) is not int
                or p["purge_report"]["purged"] != 1
            ):
                raise ValueError("positive purge count")
            if (
                type(c["report"]["counts"]["quarantined"]) is not int
                or c["report"]["counts"]["quarantined"] != 0
            ):
                raise ValueError("protected action")
            reason = {
                "dacl_refusal": "state_unreadable",
                "no_delete_share": "quarantine_failed",
                "case_alias": "busy_lock",
                "long_payload": "unfinished_work",
            }[name]
            if not action_entry(c["report"], ref["session_id"], reason):
                raise ValueError("candidate refusal witness")
            if (
                type(p["quarantine_report"]["counts"]["quarantined"]) is not int
                or p["quarantine_report"]["counts"]["quarantined"] != 1
                or not action_entry(p["quarantine_report"], ref["session_id"], None)
            ):
                raise ValueError("positive quarantine witness")
            if name == "dacl_refusal":
                if c["dacl_changed"] is not True or not dacl_reads_denied(
                    c["native_read_probe"], c["python_read_probe"]
                ):
                    raise ValueError("independent native/Python DACL denials")
                if (
                    not valid_winid(c["pinned_before"], "file")
                    or any(
                        not valid_winid(c[key], "file") or c[key] != c["pinned_before"]
                        for key in (
                            "pinned_after",
                            "path_after",
                            "read_path_before",
                            "read_path_after",
                        )
                    )
                    or c["restored_state_sha256"] != r["before"]["state_sha256"]
                ):
                    raise ValueError("DACL original file binding")
                if (
                    not isinstance(c["original_dacl_sha256"], str)
                    or not re.fullmatch("[0-9a-f]{64}", c["original_dacl_sha256"])
                    or c["original_dacl_sha256"] != c["restored_dacl_sha256"]
                ):
                    raise ValueError("actual restored DACL differs")
                for key in ("apply_api", "restore_api"):
                    api = c[key]
                    if (
                        api["api"] != "SetSecurityInfo_DACL_only"
                        or type(api["winerror"]) is not int
                        or api["winerror"] != 0
                        or type(api["flags"]) is not int
                        or api["flags"]
                        not in (
                            (4,) if key == "apply_api" else (0x80000004, 0x20000004)
                        )
                    ):
                        raise ValueError("actual DACL-only API")
                if (
                    type(c["close"]["return_value"]) is not int
                    or c["close"]["return_value"] != 1
                ):
                    raise ValueError("DACL handle closure")
            if name == "no_delete_share" and (
                type(c["share_mode"]) is not int
                or c["share_mode"] != 3
                or type(c["delete_probe"]["winerror"]) is not int
                or c["delete_probe"]["winerror"] != 32
                or not valid_winid(c["handle_identity"])
                or not valid_winid(c["path_identity"])
                or c["handle_identity"] != c["path_identity"]
                or type(c["close"]["return_value"]) is not int
                or c["close"]["return_value"] != 1
            ):
                raise ValueError("real held handle")
            if name == "case_alias" and (
                c["original"] == c["alias"]
                or c["original"].casefold() != c["alias"].casefold()
                or not valid_winid(c["original_identity"])
                or not valid_winid(c["alias_identity"])
                or c["original_identity"] != c["alias_identity"]
                or c["kernel_lock_released"] is not True
            ):
                raise ValueError("real case alias")
            if (
                name == "case_alias"
                and PureWindowsPath(c["original"])
                != PureWindowsPath(expected["fixture_root"]) / "case_alias" / "data"
            ):
                raise ValueError("alias root outside case fixture")
            if name == "long_payload" and (
                type(c["path_chars"]) is not int
                or c["path_chars"] <= 260
                or not isinstance(c["payload_path"], str)
                or len(c["payload_path"]) != c["path_chars"]
                or type(c["max_component_chars"]) is not int
                or not 1 <= c["max_component_chars"] <= 255
                or c["path_form"] != "ordinary_absolute"
                or not isinstance(c["payload_sha256"], str)
                or not re.fullmatch("[0-9a-f]{64}", c["payload_sha256"])
                or c["protected_payload_sha256"] != c["payload_sha256"]
                or p["payload_readback_sha256"] != c["payload_sha256"]
                or c["payload_absent_after_purge"] is not True
            ):
                raise ValueError("real long payload")
            if name == "long_payload" and not valid_long_path(
                c, expected, ref["session_id"]
            ):
                raise ValueError("long path shape/scope")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            errors.append(str(name) + ":" + str(exc))
    if result.get("resources_released") is not True:
        errors.append("resources_released")
    if result.get("status") != "passed":
        errors.append("overall_status")
    return errors


def valid_winid(value, kind="directory"):
    return (
        isinstance(value, dict)
        and set(value) == {"volume_serial", "file_id", "kind", "reparse_tag"}
        and type(value["volume_serial"]) is int
        and value["volume_serial"] > 0
        and isinstance(value["file_id"], str)
        and re.fullmatch("[0-9a-f]{32}", value["file_id"]) is not None
        and value["file_id"] != "0" * 32
        and value["kind"] == kind
        and type(value["reparse_tag"]) is int
        and value["reparse_tag"] == 0
    )


def action_entry(report, candidate, reason):
    return (
        isinstance(report, dict)
        and type(report.get("counts", {}).get("scanned")) is int
        and report["counts"]["scanned"] >= 1
        and not report.get("deadline_reached")
        and isinstance(report.get("entries"), list)
        and any(
            isinstance(e, dict)
            and e.get("name") == candidate
            and (
                e.get("reason") == reason
                if reason
                else e.get("verdict") == "quarantined"
            )
            for e in report["entries"]
        )
    )


def valid_long_path(condition, expected, session):
    raw = condition["payload_path"]
    path = PureWindowsPath(raw)
    base = (
        PureWindowsPath(expected["fixture_root"])
        / "long_payload"
        / "data"
        / "sessions-v2"
        / session
    )
    return (
        path.is_absolute()
        and re.fullmatch("[A-Za-z]:", path.drive) is not None
        and ".." not in path.parts
        and str(path) == raw
        and base in path.parents
        and max(map(len, path.parts)) == condition["max_component_chars"]
        and max(map(len, path.parts)) <= 255
        and len(raw) > 260
    )


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in (
        "tool-repo-root",
        "product-repo-root",
        "installed-plugin-root",
        "release-zip",
        "private-parent",
    ):
        p.add_argument("--" + flag, type=Path, required=True)
    p.add_argument("--tool-commit", required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--runtime-tree-sha256", required=True)
    p.add_argument("--release-zip-sha256", required=True)
    p.add_argument(
        "--protected-root",
        type=Path,
        action="append",
        required=True,
        help="include every authenticated native HOME; never inspected recursively",
    )
    p.add_argument("--output", type=Path)
    p.add_argument("--fixture-root", type=Path, required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--verify-result", type=Path)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    # Includes any lazy imports made by the installed runtime during a scene.
    sys.dont_write_bytecode = True
    pins = []
    result = None
    owned_output = False
    try:
        if os.name != "nt" or sys.version_info < (3, 10):
            raise Unavailable("native Windows Python3.10+ required")
        subject, installed, tool = bindings(args)
        cg = load(installed / "scripts/context_guard.py", "windows_retention_installed")
        backend = load(tool / DEPS[1], "windows_retention_backend")
        parent = plain(args.private_parent)
        private_acl(cg, parent)
        protected = [
            args.tool_repo_root,
            args.product_repo_root,
            installed,
            args.release_zip,
            Path.home() / ".codex",
            *args.protected_root,
        ]
        # Reject alternate-volume/short-name spellings before any creation.
        # Pins also prevent replacement of these exact existing roots until exit.
        for path in dict.fromkeys([parent, *protected]):
            pins.append(pin_canonical(backend, plain(path)))
        if args.verify_result:
            checked = plain(args.verify_result)
            if checked.name.lower() == "auth.json" or not within(checked, parent):
                raise ValueError("result must be a named private receipt, never auth")
            if any(not disjoint(checked, plain(p)) for p in protected):
                raise ValueError("result overlaps protected root")
            private_acl(cg, checked.parent)
            result = strict_json(checked.read_text(encoding="utf-8"))
            errors = verify_result(result, subject)
            print(
                json.dumps(
                    {"status": "failed" if errors else "passed", "errors": errors}
                )
            )
            return 1 if errors else 0
        if args.output is None or args.fixture_root is None:
            raise ValueError("output and fixture-root required")
        check_destinations(args.output, args.fixture_root, parent, protected)
        private_acl(cg, args.output.parent)
        pins.append(pin_canonical(backend, args.output.parent))
        if args.preflight:
            # Writability is tested only AFTER all path and ACL checks; no fixture
            # or final result is created. Fixed directory, exclusive random file.
            import tempfile

            with tempfile.NamedTemporaryFile(
                dir=args.output.parent, prefix=".write-probe-", delete=True
            ) as probe:
                probe.write(b"preflight")
                probe.flush()
                os.fsync(probe.fileno())
            print(
                "windows_retention_preflight=passed; writable_checked; no_fixture_written"
            )
            return 0
        result = {
            "schema": SCHEMA,
            "binding": subject,
            "status": "running",
            "cases": [],
            "resources_released": False,
            "fixture_root": str(args.fixture_root),
            "boundary": "real Windows APIs on synthetic roots; installed runtime; no login/install/model/scheduler; purge uses explicit synthetic +8d adjudication time, no OS clock mock; ordinary long paths only",
        }
        # Reserve outputs before fixture writes; never overwrite a prior run.
        with (
            args.output.open("x", encoding="utf-8", newline="") as output,
            args.output.with_suffix(".events.jsonl").open(
                "x", encoding="utf-8", newline=""
            ) as events,
        ):
            owned_output = True

            def persist():
                output.seek(0)
                output.truncate()
                json.dump(result, output, ensure_ascii=True, indent=2)
                output.flush()
                os.fsync(output.fileno())

            def emit(event):
                events.write(json.dumps(event, ensure_ascii=True) + "\n")
                events.flush()

            persist()
            try:
                private_mkdir(cg, args.fixture_root)
                with contextlib.ExitStack() as stack:
                    previous = {
                        k: os.environ.get(k)
                        for k in (
                            "CONTEXT_GUARD_DATA_DIR",
                            "CODEX_HOME",
                            "HOME",
                            "USERPROFILE",
                            "PLUGIN_DATA",
                            "CLAUDE_PLUGIN_DATA",
                            "PLUGIN_ROOT",
                        )
                    }

                    def restore_env():
                        for key, value in previous.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value

                    stack.callback(restore_env)
                    for name in CASES:
                        if any(r["status"] == "failed" for r in result["cases"]):
                            result["cases"].append({"name": name, "status": "not_run"})
                            continue
                        work = args.fixture_root / name
                        private_mkdir(cg, work)
                        os.environ.update(
                            CONTEXT_GUARD_DATA_DIR=str(work / "data"),
                            CODEX_HOME=str(work / "empty-home"),
                            HOME=str(work / "os-home"),
                            USERPROFILE=str(work / "os-home"),
                        )
                        for key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
                            os.environ.pop(key, None)
                        fixture = Fixture(cg, backend, work, emit)
                        row = scenario(name, fixture)
                        result["cases"].append(row)
                        emit({"case": name, "observed": row})
                        persist()
                result["resources_released"] = all(
                    r.get("resources")
                    == {"dacl_restored": True, "handles_closed": True}
                    for r in result["cases"]
                )
                # A consumed installed tree remains immutable after execution.
                after_subject, _installed, _tool = bindings(args)
                if after_subject != subject:
                    raise AssertionError("subject changed during execution")
                result["binding_unchanged_after_execution"] = True
                result["status"] = (
                    "passed"
                    if all(r["status"] == "passed" for r in result["cases"])
                    else "incomplete"
                    if all(r["status"] != "failed" for r in result["cases"])
                    else "failed"
                )
                errors = verify_result(result, subject)
                if result["status"] == "passed" and errors:
                    result["status"] = "failed"
                result["consumer_errors"] = errors
            except Exception as exc:
                result.update(
                    status="failed",
                    error={
                        "type": type(exc).__name__,
                        "winerror": getattr(exc, "winerror", None),
                        "message": str(exc),
                    },
                )
            finally:
                result["fixtures_retained"] = True
                persist()
        print(json.dumps({"status": result["status"], "output": str(args.output)}))
        return {"passed": 0, "incomplete": 3}.get(result["status"], 1)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(
            json.dumps(
                {
                    "status": "capability_unavailable"
                    if isinstance(exc, Unavailable)
                    else "refused",
                    "error_type": type(exc).__name__,
                    "winerror": getattr(exc, "winerror", None),
                    "reason": str(exc),
                }
            )
        )
        return 3 if isinstance(exc, Unavailable) else 2
    finally:
        failures = []
        for api, handle in reversed(pins):
            try:
                if backend.close_windows_handle(api, handle)["return_value"] != 1:
                    failures.append("root_pin_close")
            except Exception:
                failures.append("root_pin_close")
        if failures:
            # Do not report a successful receipt with an unclosed native pin.
            if owned_output and isinstance(result, dict):
                result.update(
                    status="failed",
                    resources_released=False,
                    root_pin_cleanup_errors=failures,
                )
                args.output.write_text(
                    json.dumps(result, indent=2), encoding="utf-8", newline=""
                )
            print(json.dumps({"status": "failed", "errors": failures}))
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
