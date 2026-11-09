# Native cross-version upgrade acceptance

`native_upgrade_acceptance.py` verifies one real cross-version upgrade of
Context Guard on one host: preflight inputs, an official marketplace install of
the old release, a live open task, the transition to the new release, a cold
start, and an independent consumer readback. It never logs in, copies
credentials, edits Hook trust, or touches a consumed cache or the daily HOME;
only recorded observations can satisfy a gate, and a missing host capability
stays pending, never a pass.

## Entries

Run either launcher with a target and passthrough arguments; both exec the same
Python core once with `-B`:

- POSIX sh: `tools/validation/run_native_acceptance.sh upgrade ...`
- Windows PowerShell 5.1 / 7: `tools/validation/run_native_acceptance.ps1 -Target upgrade ...`

The sibling targets `acceptance`, `retention`, and `scheduler` dispatch to
`native_acceptance.py`, `windows_retention_native.py`, and
`native_scheduler_batch.py`. A missing or refused interpreter exits 2 with an
actionable message instead of guessing.

## Actions

`--plan PLAN --output OUTPUT --auth-home HOME --other-auth-home HOME ...` plus
exactly one of:

1. `--preflight` — read-only input checks with the real execution arguments:
   absolute real paths, digest-bound release ZIP/CLI/old fixture, clean product
   and toolkit commits, runtime digest, CLI capability adoption, no link
   ancestors, hard-link aliasing, no overlap with the daily HOME or any
   authentication HOME, credential-named inputs refused before reads. A
   preflight pass proves input readiness only; it is not native acceptance.
2. `--prepare` — installs the old release into the isolated HOME through
   official operations, records the sentinel and state baselines, and writes a
   `prepare.json` receipt. A normal business review (`normal_hook_review`)
   remains pending for the live task.
3. `--run-open-transition --prepared-result PATH` — re-runs preflight, re-binds
   the prepare receipt, then drives the transition strategy from the plan
   (`observe-open` or `finish-old`), including the cold start and cleanup.
4. `--verify --prepared-result PATH --verify-output PATH` — independently
   re-derives every fact from the raw `rpc.jsonl` journal and artifacts; flags
   and summaries are never trusted on their own.

Exit codes: `0` verified/passed, `1` executed but pending or failed (write a
`review-required.json` and stop for the normal review path), `2` refused
inputs. Existing result files are never replaced.

## Per-round version bindings

Module constants bind the exact old/new pair this toolkit revision verifies:
`NEW_VERSION` and `NEW_MARKET` name the target; `OLD_MARKETS` maps each
accepted starting version to its marketplace name; `OLD_ZIP_SHA256` pins
published-release-ZIP provenance (`0.16.1`, and `0.17.0` whose marketplace
name equals `NEW_MARKET`, i.e. the stable-identity in-place route); `0.15.1`
keeps its published-commit source-export route. A release round updates these
constants to its own frozen pair in its own tool commit, so every result binds
what it actually exercised.

## Control channel and approvals

The client speaks the official JSON-RPC transport with a 2 MiB per-line cap, a
bounded row limit, and a 16 MiB journal re-read cap. Oversized rows, unknown
notifications, unmatched response IDs, unexpected server requests, and unknown
running Hooks are recorded and refused, never interpreted. Approval uses the
official `on-request` policy; there is no custom APPROVE-string input anywhere.
Hook trust is observed through the official inventory (`trustStatus`),
tool approval through observed commands matched against one approved literal,
and login is explicitly out of scope (`isolated_env` strips credential-bearing
environment keys). Offline zero-model controls run before any real-model turn.

## Records and limitations

The raw per-message journal `rpc.jsonl`, per-artifact SHA-256 digests, subject
bindings (product commit, toolkit commit, runtime digest, Python identity),
pending lists, guard diagnostics, and cleanup facts are all written to the
exclusive `--output` directory outside the checkout; prior results are
preserved. Known limitations: owned CLI/app-server process stdout and stderr
are deliberately not retained (credential-retention risk; exit codes and
`stderr_nonempty` flags are recorded instead), and one run verifies one host
and one starting version — the full upgrade matrix is the sum of its runs.
Tool faults (RPC failures) are recorded separately from product faults (Hook
diagnostics), and a run with any guard diagnostic cannot verify. Whether a
tool change invalidates earlier evidence is decided by its affected inputs and
the evidence consumers, not by the byte change alone.
