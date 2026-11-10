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
2. `--preflight-commands` — a no-model, no-login, no-trust probe of the exact
   official commands a run will issue, run before any operator trust step: the
   planned argv families are built and their executable resolved under the
   child environment; the platform launcher (`run_native_acceptance.ps1` on
   Windows, `run_native_acceptance.sh` on POSIX) is parse-checked against this
   run's argument vector (parse-only echo probes; the real batch never runs);
   the driver cwd, module search path, UTF-8 child environment and the future
   output location are probed; and the installed CLI's entry parameters
   (`--version` style, plus the Windows `-c` entry flags) are probed rather
   than assumed. Any failed probe exits nonzero naming the concrete command,
   and no operator-trust stage is reached. The opposite platform's launcher is
   recorded as a capability skip, never a pass. A pass proves command
   readiness only; it is not native acceptance.
3. `--prepare` — installs the old release into the isolated HOME through
   official operations, records the sentinel and state baselines, and writes a
   `prepare.json` receipt. A normal business review (`normal_hook_review`)
   remains pending for the live task.
4. `--run-open-transition --prepared-result PATH` — re-runs preflight, re-binds
   the prepare receipt, then drives the transition strategy from the plan
   (`observe-open` or `finish-old`), including the cold start and cleanup.
5. `--resume-wait RECEIPT --prepared-result PATH` — continues a run whose
   bounded official wait timed out (see below): it binds the pending-wait
   receipt, re-verifies the plan digest and the registration/installation
   identity, then re-enters only that wait with the recorded budget.
6. `--verify --prepared-result PATH --verify-output PATH` — independently
   re-derives every fact from the raw `rpc.jsonl` journal and artifacts; flags
   and summaries are never trusted on their own.

Exit codes: `0` verified/passed or a `wait_resolved` resume, `1` executed but
pending or failed (write a `review-required.json` and stop for the normal
review path; a `wait_pending` run also exits 1), `2` refused inputs. Existing
result files are never replaced.

Set `review_timeout_seconds` in the plan when the operator needs more time.
The default is 300 seconds and the accepted range is 1 to 1200 seconds.
The setting applies to each normal operator step (old entry disable when
required, then new Hook review). It binds to the plan and the receipts, and
the runner still requires official readback before it continues.

## Pending waits and resume

When a bounded official-confirmation wait (old-plugin disable, new Hook
review) times out, the run records status `wait_pending` — distinct from
`failed` — in its `result.json` and writes a machine-readable receipt
`wait-pending.json` beside it. The receipt binds the plan digest, the subject
digest, the `prepare.json` digest, the phase and wait name, the observed
marketplace and scoped plugin inventory at timeout, its stable
registration/installation projection, the reviewed Hook sources, the wall
clock start and the wait budget. It is never a pass and never satisfies
`--verify`.

`--resume-wait PATH/TO/wait-pending.json` (with a new `--output`) refuses a
changed plan digest or `prepare.json` digest, a result whose subject no longer
binds the receipt, or an official identity whose registration, installation,
path, or version changed since the timeout; the wait-governed `enabled` flag
is excluded from that check because the operator's manual action is the
expected change. It then re-enters only the bounded wait — official readbacks
for the old-plugin disable, or read-only `hooks/list` polls through an
observation client that never requires trust — and records `wait_resolved`
with the resolved inventory, or writes a refreshed receipt and stays
`wait_pending`. A resume never creates a HOME, never re-runs prepare,
marketplace registration, plugin add, or any destructive step, and never sets
trust programmatically. Boundary: it does not re-execute the interrupted
phase's task observations; the original `wait_pending` result stays the
authoritative phase record and remains unverifiable, so the acceptance gate
stays unsatisfied until a full run of the same plan succeeds elsewhere.

## Per-round version bindings

Module constants bind the exact old/new pair this toolkit revision verifies:
`NEW_VERSION` and `NEW_MARKET` name the target; `OLD_MARKETS` maps each
accepted starting version to its marketplace name; `OLD_ZIP_SHA256` pins
published-release-ZIP provenance (`0.16.1`, and `0.17.0` whose marketplace
name equals `NEW_MARKET`, i.e. the stable-identity in-place route); `0.15.1`
keeps its published-commit source-export route. A release round updates these
constants to its own frozen pair in its own tool commit, so every result binds
what it actually exercised.

To exercise the 0.16.1 consumer wrapper, supply `old_marketplace_root` in the
plan. Its marketplace must be `codex-context-guard-v0161` with one local
`context-guard` entry pointing to `./artifact`. Set `old_artifact` to that
direct child and extract the pinned public 0.16.1 ZIP into it unchanged. The
tool checks the wrapper manifest separately from the ZIP and validates both
paths in Codex's official readback. A plan without `old_marketplace_root`
tests the public `codex-context-guard-v016` identity.

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

One bounded summary tolerance exists: when the destructive stable plugin add
returns exit 0 but its JSON summary is missing or unreadable, the command fact
records `summary_parse_failed` with the raw stdout digest and byte length and
the transition continues — the host change has already happened, so the phase
verdict rests on the scoped plugin-list readback, the validated on-disk cache,
and the journals, and a readback that proves the add did not land still fails
the run. All other official summaries stay strict, the prepare-phase add
included.
