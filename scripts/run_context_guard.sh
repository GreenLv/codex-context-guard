#!/bin/sh
set -eu

# Codex GUI/CLI hosts may resolve `python3` to Apple's Python 3.9 even when a
# supported interpreter is installed later on PATH. Select by capability
# instead of command-name precedence, then replace this launcher process so
# stdin/stdout/stderr retain the Hook wire contract.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
        exec "$candidate" "$script_dir/context_guard.py" "$@"
    fi
done

printf '%s\n' 'Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH.' >&2
exit 2
