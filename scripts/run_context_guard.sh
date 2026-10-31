#!/bin/sh
set -eu

# Codex GUI/CLI hosts may resolve `python3` to Apple's Python 3.9 even when a
# supported interpreter is installed later on PATH. Version-suffixed names
# (python3.10..python3.14) satisfy the >=3.10 floor by name, so `command -v`
# alone is enough and the Hook hot path starts Python exactly once; only the
# generic `python3`/`python` fallback pays a capability probe. The launcher
# exec-replaces itself so stdin/stdout/stderr retain the Hook wire contract.
# Every runtime starts with -B to keep consumed caches free of bytecode.
# The stdlib-only Hook router additionally runs with -S (skip site) to stay
# under the p95 budget; the heavy core and every other CLI subcommand keep a
# normal interpreter start.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

router=0
target="$script_dir/context_guard.py"
if [ "${1:-}" = "hook" ] && [ "${2:-}" = "SessionEnd" ] && [ "$#" -eq 2 ]; then
    # Keep normal site flags, but let the thin entry start its same-process
    # budget before loading the heavy core. No second core process is added.
    target="$script_dir/cg_hook.py"
    set -- hook
elif [ "${1:-}" = "hook" ]; then
    router=1
    target="$script_dir/cg_hook.py"
fi

# Optional interpreter binding: an existing configuration records the verified
# interpreter absolute path in a plain single-line file under the selected
# HOME, so a GUI host whose PATH lacks the installed Python still starts the
# Hook. The file is read with shell builtins only — no eval, no sourcing —
# and the path is exec'd directly with quoting, never re-parsed as command
# text. An explicit configured path that is missing or not executable is an
# error distinct from "nothing configured": it never silently falls back to
# PATH probing, because that would keep a stale binding looking current.
configured=""
config_file=""
if [ -n "${CODEX_HOME:-}" ]; then
    config_file="$CODEX_HOME/context-guard/interpreter.conf"
else
    config_file="$HOME/.codex/context-guard/interpreter.conf"
fi
if [ -f "$config_file" ] && [ -r "$config_file" ]; then
    configured=$(head -n 1 "$config_file" 2>/dev/null || true)
    case "$configured" in
        /*) : ;;
        "")
            configured=""
            ;;
        *)
            printf '%s\n' "Context Guard interpreter configuration must contain an absolute path; ignoring $config_file." >&2
            configured=""
            ;;
    esac
fi
if [ -n "$configured" ]; then
    if [ ! -x "$configured" ]; then
        printf '%s\n' "Context Guard interpreter configuration is missing or not executable: $configured. Please review the Context Guard installation in Codex Plugins and the supported Python on PATH, or correct $config_file." >&2
        exit 2
    fi
    if [ "${1:-}" = "hook" ]; then
        # A replaced or non-Python executable can exit 0 with completely
        # empty output, which would silently skip the Hook. Run the real
        # runtime with stdout captured and verify it produced a Hook wire
        # result before re-emitting it; otherwise fail visibly instead of
        # skipping. stdin passes through unchanged and stderr stays direct.
        hook_out=$(mktemp "${TMPDIR:-/tmp}/cg-hook-out.XXXXXX") || {
            printf '%s\n' "Context Guard could not create a temporary file for the configured interpreter output." >&2
            exit 2
        }
        hook_exit=0
        if [ "$router" -eq 1 ]; then
            "$configured" -B -S "$target" "$@" >"$hook_out" || hook_exit=$?
        else
            "$configured" -B "$target" "$@" >"$hook_out" || hook_exit=$?
        fi
        if [ "$hook_exit" -eq 0 ]; then
            # Hook wire results are always JSON objects (at minimum "{}" for
            # the silent allow path). Output shape (first byte, brace count)
            # cannot distinguish a working runtime from an unrelated program
            # that prints similar text, and "exit 0 with empty output" proves
            # nothing either, so the configured interpreter itself must parse
            # the captured result and print a deterministic marker. Only a
            # program that actually executes the Python json parse above and
            # finds a JSON object can emit that marker: empty output,
            # incomplete or malformed JSON, a non-object value, or an
            # unrelated program that ignores arguments and prints its own
            # (or no) text all fail visibly with no state written.
            wire_rc=0
            wire_noise=$("$configured" -I -S -c '
import json, sys
try:
    payload = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(3)
if not isinstance(payload, dict):
    raise SystemExit(4)
print("CG-HOOK-WIRE-VERIFIED")
' "$hook_out" 2>/dev/null) || wire_rc=$?
            if [ "$wire_rc" -ne 0 ] || [ "$wire_noise" != "CG-HOOK-WIRE-VERIFIED" ]; then
                printf '%s\n' "Context Guard interpreter configuration is not a working Context Guard runtime: $configured produced output that is not a Hook wire result. Please review the Context Guard installation in Codex Plugins and the supported Python on PATH, or correct $config_file." >&2
                rm -f "$hook_out"
                exit 2
            fi
        fi
        cat "$hook_out"
        rm -f "$hook_out"
        exit "$hook_exit"
    fi
    if [ "$router" -eq 1 ]; then
        exec "$configured" -B -S "$target" "$@"
    fi
    exec "$configured" -B "$target" "$@"
fi

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
        if [ "$router" -eq 1 ]; then
            exec "$candidate" -B -S "$target" "$@"
        fi
        exec "$candidate" -B "$target" "$@"
    fi
done

for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && probe_python_runtime "$candidate"; then
        if [ "$router" -eq 1 ]; then
            exec "$candidate" -B -S "$target" "$@"
        fi
        exec "$candidate" -B "$target" "$@"
    fi
done

# GUI hosts may have a system-only PATH. Only after normal PATH discovery
# fails, probe these explicit global installation locations. Never enumerate
# personal directories or create an interpreter binding. A successful exit by
# itself is insufficient: the isolated Python probe must emit its exact marker.
for candidate in \
    /opt/homebrew/bin/python3 \
    /opt/homebrew/bin/python3.14 \
    /opt/homebrew/bin/python3.13 \
    /opt/homebrew/bin/python3.12 \
    /opt/homebrew/bin/python3.11 \
    /opt/homebrew/bin/python3.10 \
    /usr/local/bin/python3 \
    /usr/local/bin/python3.14 \
    /usr/local/bin/python3.13 \
    /usr/local/bin/python3.12 \
    /usr/local/bin/python3.11 \
    /usr/local/bin/python3.10 \
    /opt/anaconda3/bin/python3 \
    /opt/anaconda3/bin/python \
    /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.10/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/Current/bin/python3
do
    [ -f "$candidate" ] && [ -x "$candidate" ] || continue
    probe_python_runtime "$candidate" || continue
    if [ "$router" -eq 1 ]; then
        exec "$candidate" -B -S "$target" "$@"
    fi
    exec "$candidate" -B "$target" "$@"
done

printf '%s\n' 'Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH or in the supported global installation locations. Make Python discoverable to the GUI host or configure interpreter.conf with its absolute path.' >&2
exit 2
