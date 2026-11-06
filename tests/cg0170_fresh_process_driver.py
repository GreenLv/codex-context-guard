"""One retention maintenance invocation in a FRESH process (0.17.0 R5).

Test-only driver for plan D1 evidence: every call is a new interpreter, the
same lifetime as the scheduled ``cleanup --apply`` executor, so nothing but
on-disk state carries from one invocation to the next. It runs the real
``cleanup_old_sessions`` entry under a virtual clock:

* every namespace or quarantine-directory entry the product lists costs
  ``--list-ms`` (the known prefix included);
* every adjudication costs ``--adj-ms``;
* every listed entry inside a quarantined object being purged costs
  ``--purge-ms``;
* every deadline check (``time.monotonic``) costs ``--epsilon-us``, so a
  checked loop over hints, records or windows is never free.

Work the product performs without a deadline check (one C-level sort of the
names a listing just produced, one bounded hint/state read or write) is not
charged by this model; the real wall clock charges it in production.
``--order sorted`` replays a stable adversarial listing order (names sorted,
so a tail entry is listed last); the order is materialized by the harness
only, its cost is still charged per yielded entry, and nothing in the
product depends on it. Synthetic temporary roots only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_product():
    spec = importlib.util.spec_from_file_location(
        "context_guard_fresh_process", ROOT / "scripts" / "context_guard.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def is_purge_object_unlink(path, dir_fd, quarantine_dir: Path) -> bool:
    """Count object removals in both real platform call forms, not records.

    POSIX purges unlink relative to the held directory descriptor; Windows
    purges use full paths below a quarantine object. Files directly in the
    quarantine directory are transaction metadata and must not trigger the
    object-removal crash point.
    """
    if dir_fd is not None:
        return True
    try:
        parts = Path(os.fsdecode(path)).absolute().relative_to(
            quarantine_dir.absolute()).parts
    except (TypeError, ValueError):
        return False
    return len(parts) > 1


def purge_unlink_patch(quarantine_dir: Path, on_unlink, *, use_pathlib: bool):
    """Observe the actual deletion entrypoint once, including Python 3.10.

    Windows product code calls Path.unlink. Python 3.10 pathlib caches its
    OS accessor at import, so replacing os.unlink alone cannot observe it.
    POSIX product code instead calls os.unlink with a held directory fd.
    Patch only one layer to avoid counting a deletion twice on newer Python.
    """
    if use_pathlib:
        real_path_unlink = Path.unlink

        def path_unlink(path, *args, **kwargs):
            result = real_path_unlink(path, *args, **kwargs)
            if is_purge_object_unlink(path, None, quarantine_dir):
                on_unlink()
            return result

        return mock.patch.object(Path, "unlink", new=path_unlink)

    real_unlink = os.unlink

    def unlink(path, *args, **kwargs):
        result = real_unlink(path, *args, **kwargs)
        if is_purge_object_unlink(path, kwargs.get("dir_fd"), quarantine_dir):
            on_unlink()
        return result

    return mock.patch.object(os, "unlink", new=unlink)


def windows_text_tempfile():
    """A ``tempfile`` stand-in whose text-mode NamedTemporaryFile translates
    ``\\n`` to ``\\r\\n`` whenever ``newline`` is None (the default) -- the
    behavior of text files on Windows (R6, N1)."""
    import tempfile
    import types

    def named(*args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "w+b")
        if "b" not in mode and kwargs.get("newline") is None:
            kwargs["newline"] = "\r\n"
        return tempfile.NamedTemporaryFile(*args, **kwargs)
    shim = types.SimpleNamespace(**{name: getattr(tempfile, name)
                                    for name in dir(tempfile)
                                    if not name.startswith("__")})
    shim.NamedTemporaryFile = named
    return shim


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--budget-ms", type=float, required=True)
    parser.add_argument("--list-ms", type=float, default=1.0)
    parser.add_argument("--adj-ms", type=float, default=0.0)
    parser.add_argument("--purge-ms", type=float, default=0.0)
    parser.add_argument("--epsilon-us", type=float, default=1.0)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--order", choices=("sorted", "real"), default="sorted")
    parser.add_argument("--frozen-mtime", action="store_true")
    parser.add_argument("--future-days", type=float, default=0.0)
    parser.add_argument("--crash", default="")
    parser.add_argument("--no-birth-time", action="store_true",
                        help="model a filesystem that reports no creation time")
    parser.add_argument("--windows-newlines", action="store_true",
                        help="emulate Windows text-mode newline translation "
                             "(CRLF) for the product's text writes")
    parser.add_argument("--create-during-listing", default="",
                        help="NAME:AFTER_ENTRIES:registered|legacy:TEMPLATE_DIR")
    args = parser.parse_args(argv)

    cg = load_product()
    data_dir = args.data_dir
    namespace = data_dir / cg.V2_NAMESPACE
    qdir = cg._retention_quarantine_dir(data_dir)
    clock = [1000.0]
    epsilon = args.epsilon_us / 1_000_000.0

    def monotonic():
        clock[0] += epsilon
        return clock[0]

    real_scandir = os.scandir
    created = {"done": False}

    def create_during_listing() -> None:
        name, _after, kind, template = args.create_during_listing.split(":", 3)
        target = namespace / name
        shutil.copytree(template, target)
        if kind == "registered":
            cg._add_cleanup_registry_entries(data_dir, [name])

    class Charged:
        def __init__(self, source, cost, names=None, hook_after=None):
            self.source = source
            self.cost = cost
            self.names = iter(names) if names is not None else None
            self.count = 0
            self.hook_after = hook_after

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self.names) if self.names is not None else next(self.source)
            clock[0] += self.cost
            self.count += 1
            if (self.hook_after is not None and not created["done"]
                    and self.count == self.hook_after):
                created["done"] = True
                create_during_listing()
            return entry

        def close(self):
            self.source.close()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    def scandir(path=None):
        source = real_scandir(path) if path is not None else real_scandir()
        if isinstance(path, int):
            return Charged(source, args.purge_ms / 1000.0)
        target = Path(path)
        if target in (namespace, qdir):
            names = None
            if args.order == "sorted":
                names = sorted(source, key=lambda entry: entry.name)
            hook = None
            if target == namespace and args.create_during_listing:
                hook = int(args.create_during_listing.split(":", 2)[1])
            return Charged(source, args.list_ms / 1000.0, names, hook)
        if target.parent == qdir or qdir in target.parents:
            return Charged(source, args.purge_ms / 1000.0)
        return source

    patches = [
        mock.patch.object(cg.time, "monotonic", side_effect=monotonic),
        mock.patch.object(cg.os, "scandir", side_effect=scandir),
    ]
    real_adjudicate = cg._retention_adjudicate

    def adjudicate(*a, **k):
        clock[0] += args.adj_ms / 1000.0
        return real_adjudicate(*a, **k)
    patches.append(mock.patch.object(cg, "_retention_adjudicate", side_effect=adjudicate))

    if args.frozen_mtime:
        real_facts = cg._discovery_dir_facts

        def frozen(path):
            facts = real_facts(path)
            if facts and facts["mtime_ns"] is not None:
                facts = dict(facts, mtime_ns=1)
            return facts
        patches.append(mock.patch.object(cg, "_discovery_dir_facts", side_effect=frozen))

    if args.future_days:
        real_datetime = cg.dt.datetime
        moment = real_datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=args.future_days)

        class Future(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return moment if tz is not None else moment.replace(tzinfo=None)
        patches.append(mock.patch.object(cg.dt, "datetime", Future))

    crash, _, ordinal = args.crash.partition("#")
    wanted = int(ordinal or 1)
    seen = {"count": 0}

    def crash_after(name):
        real = getattr(cg, name)

        def wrapped(*a, **k):
            result = real(*a, **k)
            seen["count"] += 1
            if seen["count"] == wanted:
                sys.stdout.flush()
                os._exit(137)
            return result
        patches.append(mock.patch.object(cg, name, side_effect=wrapped))

    if crash == "attempt_open":
        crash_after("_discovery_write_state")
    elif crash == "journal_append":
        crash_after("_discovery_append")
    elif crash == "listing_end":
        crash_after("_discovery_list")
    elif crash == "snapshot":
        crash_after("_discovery_write_snapshot")
    elif crash == "commit":
        crash_after("_discovery_commit")
    elif crash == "record_write":
        crash_after("_retention_write_record")
    elif crash == "before_finish":
        def die(*_a, **_k):
            sys.stdout.flush()
            os._exit(137)
        patches.append(mock.patch.object(cg, "_discovery_finish", side_effect=die))
    elif crash == "rotation":
        real_replace = os.replace

        def replace(src, dst, *a, **k):
            result = real_replace(src, dst, *a, **k)
            if str(dst).endswith(cg._DISCOVERY_MERGING_SUFFIX):
                seen["count"] += 1
                if seen["count"] == wanted:
                    os._exit(137)
            return result
        patches.append(mock.patch.object(cg.os, "replace", side_effect=replace))
    elif crash == "purge_unlink":
        def unlinked():
            seen["count"] += 1
            if seen["count"] == wanted:
                os._exit(137)
        patches.append(purge_unlink_patch(
            qdir, unlinked, use_pathlib=os.name == "nt"))
    elif crash:
        raise SystemExit(f"unknown crash point {crash}")

    if args.windows_newlines:
        patches.append(mock.patch.object(cg, "tempfile", windows_text_tempfile()))
    if args.no_birth_time:
        patches.append(mock.patch.object(cg, "_retention_birth_ns", return_value=None))

    for patch in patches:
        patch.start()
    start = clock[0]
    report = cg.cleanup_old_sessions(
        data_dir, apply=args.apply, deadline=start + args.budget_ms / 1000.0)
    spent = clock[0] - start
    for patch in reversed(patches):
        patch.stop()
    out = {
        "backlog": report.get("backlog"),
        "scan_complete": report.get("scan_complete"),
        "capacity_exceeded": report.get("capacity_exceeded"),
        "records_scan_complete": report.get("records_scan_complete"),
        "discovery": report.get("discovery"),
        "counts": report.get("counts"),
        "purge": report.get("purge"),
        "recovery": report.get("recovery"),
        "unknown_records": report.get("unknown_records"),
        "entries": [[entry.get("name"), entry.get("verdict"), entry.get("reason")]
                    for entry in report.get("entries", [])],
        "virtual_ms": round(spent * 1000.0, 4),
        "budget_ms": args.budget_ms,
    }
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
