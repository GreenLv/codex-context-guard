#!/bin/sh
set -eu

# Codex GUI/CLI hosts may resolve `python3` to Apple's Python 3.9 even when a
# supported interpreter is installed later on PATH. Version-suffixed names
# (python3.10..python3.14) satisfy the >=3.10 floor by name, so `command -v`
# alone is enough and the Hook hot path starts Python exactly once; only the
# generic `python3`/`python` fallback pays a capability probe. The launcher
# exec-replaces itself so stdin/stdout/stderr retain the Hook wire contract.
# The stdlib-only Hook router additionally runs with -S (skip site) to stay
# under the p95 budget; the heavy core and every other CLI subcommand keep a
# normal interpreter start.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

router=0
target="$script_dir/context_guard.py"
if [ "${1:-}" = "hook" ]; then
    router=1
    target="$script_dir/cg_hook.py"
fi

for candidate in python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if [ "$router" -eq 1 ]; then
            exec "$candidate" -S "$target" "$@"
        fi
        exec "$candidate" "$target" "$@"
    fi
done

for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
        if [ "$router" -eq 1 ]; then
            exec "$candidate" -S "$target" "$@"
        fi
        exec "$candidate" "$target" "$@"
    fi
done

printf '%s\n' 'Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH.' >&2
exit 2
