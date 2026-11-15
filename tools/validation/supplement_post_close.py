"""Read-only supplement for a retained result from the supported v2 verifier.

Runs the original source preflight and all evidence checks with an exact full
preimage. Only the known baseline verifier implementation is supported. It starts read-only local Git/CLI/runtime-scope children; it never
starts an app-server/model, installs, edits state or changes original records.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

SCHEMA = "cg-between-turn-post-close-supplement/v1"
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
LIMIT = 16 * 1024 * 1024
SENSITIVE = re.compile(
    r"^(?:auth\.json(?:\..*)?|credentials?(?:\.json)?|tokens?(?:\.json)?|secrets?(?:\.json)?|\.env(?:\..*)?|\.netrc|_netrc|\.ssh|\.aws)$|.*(?:token|password|secret|credential).*\.json$|.*\.(?:pem|key|p12|pfx)$",
    re.IGNORECASE,
)
_GIT_PATH = None
_GIT_SHA = None
READER_FILES = (
    "supplement_post_close.py",
    "shared_verify.py",
    "postclose_transition.py",
    "state_relation.py",
)


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def isolate_bytecode():
    """Do not import unchecked existing pyc or write a new bytecode cache."""
    prefix = Path(tempfile.gettempdir()) / ("ccg-supplement-" + uuid.uuid4().hex)
    need(not prefix.exists() and not prefix.is_symlink(), "bytecode_prefix_exists")
    sys.pycache_prefix = str(prefix)
    sys.dont_write_bytecode = True


# Apply before even the independently verified reader's first local import.
isolate_bytecode()
if __package__:
    from . import shared_verify
else:
    import shared_verify


def safe_bytes(path, limit=LIMIT):
    """Single-link, no-reparse, bounded, stable-handle input on both OSes."""
    path = Path(path)
    need(
        path.is_absolute() and all(not SENSITIVE.fullmatch(x) for x in path.parts),
        "absolute_non_sensitive_input_required",
    )
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        need(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400,
            "linked_input",
        )
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and before.st_size <= limit,
        "invalid_input_file",
    )
    if os.name == "nt":
        import msvcrt
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
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        need(handle != ctypes.c_void_p(-1).value, "input_open")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            api.CloseHandle(handle)
            raise
    else:
        need(hasattr(os, "O_NOFOLLOW"), "nofollow_unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    def identity(value):
        return (
            value.st_dev,
            value.st_ino,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
        )

    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        need(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and not getattr(opened, "st_file_attributes", 0) & 0x400
            and identity(opened) == identity(before),
            "input_open_drift",
        )
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    need(
        len(data) <= limit
        and identity(before) == identity(after) == identity(final)
        and before.st_ctime_ns == final.st_ctime_ns
        and opened.st_ctime_ns == after.st_ctime_ns,
        "input_read_drift",
    )
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        need(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400,
            "linked_input_after_read",
        )
    return data


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    def no_constant(_):
        raise Refused("invalid_json_constant")

    try:
        value = json.loads(
            raw.decode("utf8"), object_pairs_hook=pairs, parse_constant=no_constant
        )
    except (UnicodeError, ValueError):
        raise Refused("invalid_json") from None
    need(type(value) is dict, "json_object_required")
    return value


def source_digest_map(repo):
    """Mirror e78 daily._helper_identities before loading any product module."""
    values = {}
    for root in (repo / "scripts", repo / "tools/validation"):
        for path in sorted(root.glob("*.py")):
            need(len(values) < 256, "helper_limit")
            values[path.relative_to(repo).as_posix()] = sha(safe_bytes(path))
    extra = [repo / "tools/guard_state_migration.py"]
    extra += [
        repo / "tools/validation" / name
        for name in (
            "run_daily_upgrade.sh",
            "run_daily_upgrade.ps1",
            "runtime_activity_windows.ps1",
        )
    ]
    for path in extra:
        if path.is_file():
            values[path.relative_to(repo).as_posix()] = sha(safe_bytes(path))
    return values


def digest_mapping(value):
    raw = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    return sha(raw)


def readonly_git(repo, *args):
    """Use one fixed executable per process, with no shell or Git hooks."""
    global _GIT_PATH, _GIT_SHA  # Bound once for this process.
    if _GIT_PATH is None:
        found = shutil.which("git")
        need(found is not None, "git_unavailable")
        _GIT_PATH = Path(found).resolve(strict=True)
        _GIT_SHA = sha(_GIT_PATH.read_bytes())
    need(sha(_GIT_PATH.read_bytes()) == _GIT_SHA, "git_identity_drift")
    out = subprocess.run(
        [
            str(_GIT_PATH),
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(repo),
            *args,
        ],
        capture_output=True,
        timeout=20,
        check=False,
    )
    need(
        out.returncode == 0 and sha(_GIT_PATH.read_bytes()) == _GIT_SHA,
        "git_failed_or_drift",
    )
    return out.stdout


def verify_original_checkout(repo, commit, helpers):
    """Verify the original Git subject before executing any original code."""
    need(
        repo.is_absolute()
        and all(not SENSITIVE.fullmatch(x) for x in repo.parts)
        and type(commit) is str
        and HEX40.fullmatch(commit) is not None,
        "original_repo_identity",
    )
    need(
        readonly_git(repo, "rev-parse", "HEAD").decode("ascii").strip() == commit,
        "original_head_drift",
    )
    need(
        not readonly_git(repo, "status", "--porcelain", "--untracked-files=all"),
        "original_worktree_dirty",
    )
    names = sorted(
        set(helpers)
        | {
            "tools/validation/native_between_turns_acceptance.py",
            "tools/validation/hook_failure_diagnostics.py",
        }
    )
    readonly_git(repo, "ls-files", "--error-unmatch", "--", *names)
    need(source_digest_map(repo) == helpers, "original_helper_drift")


def verified_reader(manifest_path, manifest_sha):
    """Separate reader-source identity from the original producer identity."""
    need(HEX64.fullmatch(manifest_sha) is not None, "reader_manifest_sha")
    raw = safe_bytes(manifest_path)
    need(sha(raw) == manifest_sha, "reader_manifest_drift")
    manifest = strict(raw)
    need(
        set(manifest)
        == {"schema", "source_commit", "baseline_function_sha256", "files"}
        and manifest["schema"] == "cg-post-close-reader-identity/v1"
        and isinstance(manifest["source_commit"], str)
        and HEX40.fullmatch(manifest["source_commit"]) is not None
        and manifest["baseline_function_sha256"]
        == shared_verify.BASELINE_FUNCTION_SHA256
        and type(manifest["files"]) is dict
        and set(manifest["files"]) == set(READER_FILES),
        "reader_manifest_shape",
    )
    directory = Path(__file__).resolve().parent
    reader_root = directory.parent.parent
    paths = [directory / name for name in READER_FILES]
    for name, path in zip(READER_FILES, paths):
        need(
            HEX64.fullmatch(manifest["files"][name]) is not None
            and sha(safe_bytes(path)) == manifest["files"][name],
            "reader_file_drift",
        )
    need(
        readonly_git(reader_root, "rev-parse", "HEAD").decode("ascii").strip()
        == manifest["source_commit"],
        "reader_head_drift",
    )
    need(
        not readonly_git(reader_root, "status", "--porcelain", "--untracked-files=all"),
        "reader_worktree_dirty",
    )
    relative = [str(path.relative_to(reader_root)) for path in paths]
    readonly_git(reader_root, "ls-files", "--error-unmatch", "--", *relative)
    for name, path in zip(READER_FILES, paths):
        need(sha(safe_bytes(path)) == manifest["files"][name], "reader_file_drift")
    need(
        Path(shared_verify.__file__).resolve()
        == (directory / "shared_verify.py").resolve(),
        "reader_module_origin",
    )
    return {
        "source_commit": manifest["source_commit"],
        "manifest_sha256": manifest_sha,
        "files": manifest["files"],
    }


def protected_inputs(args, ctx, plan, output):
    """Directories whose contents are part of an immutable source or input."""
    return [
        ctx["repo"],
        ctx["home"],
        output,
        Path(__file__).resolve().parents[2],
        ctx["artifact"],
        Path(ctx["normalized_plan"]["old_artifact_dir"]),
        Path(plan["zip"]).parent,
        Path(plan["old_zip"]).parent,
        Path(args.preimage).parent,
        Path(args.plan).parent,
        Path(args.reader_manifest).parent,
    ]


def verify_evidence_readback(output, evidence):
    """Re-read the evidence already restricted to original core's allowlist."""
    need(type(evidence) is dict, "original_evidence_shape")
    for name, digest in evidence.items():
        need(
            type(name) is str
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts
            and type(digest) is str
            and HEX64.fullmatch(digest) is not None
            and sha(safe_bytes(Path(output) / name)) == digest,
            "original_evidence_drift",
        )


def prepare(args):
    """Validate actual args; e78 preflight performs bounded read-only host work."""
    reader = verified_reader(args.reader_manifest, args.reader_manifest_sha256)
    for digest in (args.result_sha256, args.sidecar_sha256):
        need(HEX64.fullmatch(digest) is not None, "original_digest_shape")
    plan_raw = safe_bytes(args.plan)
    plan = strict(plan_raw)
    need("_native_plan_sha256" not in plan, "reserved_plan_field")
    plan["_native_plan_sha256"] = sha(plan_raw)
    output = Path(args.output)
    result_raw = safe_bytes(output / "result.json")
    sidecar_raw = safe_bytes(output / "independent-verification.json")
    need(
        sha(result_raw) == args.result_sha256
        and sha(sidecar_raw) == args.sidecar_sha256,
        "original_result_or_sidecar_drift",
    )
    result, sidecar = strict(result_raw), strict(sidecar_raw)
    original_status = sidecar.get("status")
    need(
        result.get("status") in ("provisional_cli_native", "passed_cli_native")
        and sidecar.get("schema") == "cg-between-turn-independent/v2"
        and original_status in ("failed", "passed")
        and (original_status != "failed" or sidecar.get("reason") == "Refused")
        and sidecar.get("result_sha256") == args.result_sha256,
        "original_sidecar_binding",
    )
    subject = result.get("subject")
    need(
        type(subject) is dict
        and subject.get("commit") == plan.get("commit")
        and subject.get("native_plan_sha256") == plan["_native_plan_sha256"]
        and isinstance(subject.get("producer_sha256"), str)
        and HEX64.fullmatch(subject["producer_sha256"]) is not None,
        "original_subject",
    )
    evidence = result.get("evidence")
    need(
        type(evidence) is dict and isinstance(evidence.get("old-after.json"), str),
        "original_evidence",
    )
    after_raw = safe_bytes(output / "old-after.json")
    need(sha(after_raw) == evidence["old-after.json"], "old_after_binding")
    after = strict(after_raw)
    preimage_raw = safe_bytes(args.preimage)
    need(sha(preimage_raw) == after.get("sha256"), "preimage_binding")
    repo = Path(plan["repo"])
    need(
        repo.is_absolute() and all(not SENSITIVE.fullmatch(x) for x in repo.parts),
        "original_repo_path",
    )
    producer = repo / "tools/validation/native_between_turns_acceptance.py"
    code = safe_bytes(producer)
    need(sha(code) == subject["producer_sha256"], "original_producer_bytes")
    start = code.find(b"def independent_verify(")
    end = code.find(b"\n\ndef wait_for_activity(", start)
    need(
        start >= 0
        and end > start
        and sha(code[start:end]) == shared_verify.BASELINE_FUNCTION_SHA256,
        "unsupported_original_verifier",
    )
    helpers = source_digest_map(repo)
    need(
        digest_mapping(helpers) == subject.get("helper_closure_sha256"),
        "original_helper_closure",
    )
    verify_original_checkout(repo, plan.get("commit"), helpers)
    need(
        sha(safe_bytes(producer)) == subject["producer_sha256"],
        "original_producer_drift",
    )
    need(
        not any(name.split(".")[0] in ("scripts", "tools") for name in sys.modules)
        and "postclose_transition" not in sys.modules
        and "state_relation" not in sys.modules,
        "product_modules_preloaded",
    )
    # Load only independently bound reader bytes, never a similarly named
    # module selected from ambient sys.path. The source subject remains e78.
    directory = Path(__file__).resolve().parent
    for name in ("state_relation", "postclose_transition"):
        path = directory / (name + ".py")
        source = safe_bytes(path)
        need(sha(source) == reader["files"][path.name], "reader_module_drift")
        spec = importlib.util.spec_from_file_location(name, path)
        need(spec is not None and spec.loader is not None, "reader_module_unavailable")
        local = importlib.util.module_from_spec(spec)
        sys.modules[name] = local
        exec(compile(source, str(path), "exec"), local.__dict__)  # noqa: S102 -- bound reader

    sys.path.insert(0, str(repo))
    spec = importlib.util.spec_from_file_location("ccg_e78_retained_original", producer)
    need(spec is not None and spec.loader is not None, "original_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    # Execute the exact already checked source, with its original real __file__.
    sys.modules[spec.name] = module
    exec(compile(code, str(producer), "exec"), module.__dict__)  # noqa: S102 -- validated old source
    need(
        module.producer_path() == producer.resolve()
        and module.sha(producer) == subject["producer_sha256"],
        "original_producer_path",
    )
    ctx = module.preflight(plan, output, after=True)
    ctx["native_plan_path"] = module.regular(args.plan)
    need(ctx["helpers"] == helpers, "original_live_helper_closure")
    receipt = Path(args.receipt)
    ctx["u"]._new_outside(receipt, protected_inputs(args, ctx, plan, output))
    return reader, module, ctx, plan, result, sidecar, after, sha(preimage_raw)


def run(args):
    reader, module, ctx, plan, result, sidecar, after, preimage_sha = prepare(args)
    if args.preflight:
        return {"schema": SCHEMA, "status": "preflight_read_only_only"}
    proof = shared_verify.verify_core(
        module, ctx, plan, Path(args.output), preimage_path=Path(args.preimage)
    )
    # Preserve the original failed result/sidecar and the full preimage exactly.
    need(
        sha(safe_bytes(Path(args.output) / "result.json")) == args.result_sha256
        and sha(safe_bytes(Path(args.output) / "independent-verification.json"))
        == args.sidecar_sha256
        and sha(safe_bytes(args.preimage)) == preimage_sha,
        "original_evidence_drift",
    )
    need(
        sha(safe_bytes(args.plan)) == plan["_native_plan_sha256"]
        and source_digest_map(ctx["repo"]) == ctx["helpers"],
        "original_source_drift",
    )
    verify_evidence_readback(Path(args.output), result["evidence"])
    for name, digest in reader["files"].items():
        need(
            sha(safe_bytes(Path(__file__).resolve().parent / name)) == digest,
            "reader_file_drift",
        )
    final = module.snapshot(ctx, result["gates"]["old_model"]["thread"])
    need(
        final["root"] == after["root"] and final["sha256"] == proof["current_sha256"],
        "live_state_drift_after_readback",
    )
    receipt = {
        "schema": SCHEMA,
        "status": "supplement_verified",
        "original_independent_status": sidecar["status"],
        "original": {
            "commit": plan["commit"],
            "producer_sha256": result["subject"]["producer_sha256"],
            "helper_closure_sha256": result["subject"]["helper_closure_sha256"],
            "plan_sha256": plan["_native_plan_sha256"],
            "result_sha256": args.result_sha256,
            "sidecar_sha256": args.sidecar_sha256,
            "old_after_evidence_sha256": result["evidence"]["old-after.json"],
            "preimage_sha256": preimage_sha,
        },
        "reader": reader,
        "state_relation": proof["relation"],
        "current_state_sha256": proof["current_sha256"],
        "session_end_event_observed": False,
        "gui": "unobserved",
    }
    module.write(Path(args.receipt), receipt)
    return {
        "schema": SCHEMA,
        "status": "supplement_verified",
        "receipt_sha256": sha(safe_bytes(args.receipt)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--preimage", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--result-sha256", required=True)
    parser.add_argument("--sidecar-sha256", required=True)
    parser.add_argument("--reader-manifest", required=True, type=Path)
    parser.add_argument("--reader-manifest-sha256", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--verify-retained", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args)))
        return 0
    except Exception:  # noqa: BLE001 -- suppress private paths and exception content.
        print(json.dumps({"schema": SCHEMA, "status": "refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
