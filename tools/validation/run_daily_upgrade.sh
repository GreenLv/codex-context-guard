#!/bin/sh
# POSIX sh thin launcher for the daily-upgrade entry.
#
# Target runtime: POSIX sh (dash/bash/zsh compatible). The PowerShell twin is
# run_daily_upgrade.ps1 (PowerShell 5.1 and 7). Both exec the same testable
# Python core with passthrough arguments, so either shell starts exactly one
# Python process and stdout/stderr/stdin keep the tool wire contract.
#
# Usage: run_daily_upgrade.sh daily [args...]
#   daily  tools/validation/daily_upgrade.py
#
# Every runtime starts with -B so the source checkout stays free of bytecode.
# A missing or refused interpreter exits 2 with an actionable message and
# never falls back to a random command.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Real-entry probe mode: prints the launcher's parsed argument vector one
# word per line and exits 0 without touching any target. This lets the
# command preflight prove the REAL launcher parses and passes this run's
# argv (the parse-only probe cannot).
if [ "${1:-}" = "--print-argv" ]; then
    shift
    for word in "$@"; do
        printf '%s\n' "$word"
    done
    exit 0
fi

case "${1:-}" in
    daily) target="$script_dir/daily_upgrade.py" ;;
    *)
        printf '%s\n' "usage: $0 daily [args...]" >&2
        exit 2
        ;;
esac
[ -f "$target" ] || {
    printf '%s\n' "daily upgrade target module is missing: $target" >&2
    exit 2
}
shift

probe_python_runtime() {
    python_probe=""
    python_probe=$("$1" -B -I -S -c '
import sys
if sys.version_info < (3, 10):
    raise SystemExit(2)
print("CG-PYTHON-3.10-RUNTIME-VERIFIED")
' 2>/dev/null) || return 1
    [ "$python_probe" = "CG-PYTHON-3.10-RUNTIME-VERIFIED" ]
}

for candidate in python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1; then
        exec "$candidate" -B "$target" "$@"
    fi
done

for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && probe_python_runtime "$candidate"; then
        exec "$candidate" -B "$target" "$@"
    fi
done

printf '%s\n' 'The daily-upgrade entry requires Python 3.10 or newer, but no supported interpreter was found on PATH. Make a supported Python discoverable to this shell and retry.' >&2
exit 2
