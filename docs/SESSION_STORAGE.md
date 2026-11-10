# Session storage, upgrades and cleanup

In 0.17.1, installing or updating Context Guard leaves its task records in place. Upgrading within the same plugin entry can read existing schema 13 records. Switching entries leaves those records under the entry that wrote them. If you want to look up a task from the new entry, the [migration tool](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md) can preview and copy supported `sessions-v2` records on the same machine. Older `sessions` directories stay with the original plugin.

Session cleanup was disabled in 0.16.0 and 0.16.1. Version 0.17.0 restored it as an opt-in maintenance command, and 0.17.1 keeps that behavior. The command previews by default. Installing the plugin neither enables a retention policy nor creates a scheduled job. Ending a session saves state and performs no sweep.

## Keep old tasks working

Finish tasks that still need the old plugin before changing its entry. If they need more time, keep them in a separately configured Codex environment that still loads that version. Check the Hook source in the actual client. A cache directory on disk does not tell you which version a running task loads. For example, Codex CLI 0.158.0 on Windows was observed loading the new Hook on an old task's next turn after an in-place upgrade.

The [0.17.1 upgrade guide](UPGRADE_0_17_1.md) covers which installation routes switch entries, how to review the new Hooks, and when copying records is useful. Copying supported records does not transfer Hook trust or move an active task into a different environment. See [compatibility](COMPATIBILITY.md) and [local acceptance](LOCAL_ACCEPTANCE.md) for exact host results.

## Preview cleanup

First identify the entry with `codex plugin list --json` in the Codex environment you want to inspect. If you have more than one entry or data directory, run the [migration tool's read-only inventory](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md#stages) against that environment's configuration directory. Use the data-root path listed for the intended entry. Keep the inventory and any cleanup report on your machine.

From the extracted release directory, run the following with that private data-root path. On Windows, replace `python3` with `py -3`.

```shell
python3 scripts/context_guard.py cleanup --data-dir "/path/to/plugin-data"
```

Preview reports eligible sessions and why it keeps others. It makes no changes to session data. The command requires `--data-dir` and exits with code 2 when it is missing. Use `--policy show` with the same data root to see whether maintenance and permanent deletion are allowed.

When you first enable the default policy, apply can move eligible sessions to quarantine after 30 days and permanently delete them after seven further days in quarantine. To enable quarantine without permanent deletion, run the first command below. The second command saves a preview. Inspect it before running the third command, which applies only the saved selection. Use an unused local filename for the preview.

```shell
python3 scripts/context_guard.py cleanup --data-dir "/path/to/plugin-data" --policy enable --no-purge
python3 scripts/context_guard.py cleanup --data-dir "/path/to/plugin-data" --save-manifest "/path/to/cleanup-preview.json"
python3 scripts/context_guard.py cleanup --data-dir "/path/to/plugin-data" --apply-manifest "/path/to/cleanup-preview.json"
```

`--apply` instead uses the selection built by that invocation. To put back a quarantined session, pass `--restore <name>` with the same data root. Restore checks the identity and contents and requires a free destination. Scheduled maintenance is a separate choice. Use `--maintenance-status` to check whether a job is present and enabled.

## Where the records live

Here, `CODEX_HOME` is the Codex configuration and task-data directory. A direct command without an explicit plugin data root uses the active `CODEX_HOME` for its fallback data directory, `<home>/context-guard`. An existing `interpreter.conf` there can point a Hook at a Python interpreter when the GUI host's PATH cannot find it. The launcher checks that interpreter on each start. The marketplace installation does not create a binding.

New sessions use `sessions-v2/<id>` beneath the plugin data root. The current runtime looks there first, then reads legacy `sessions/<id>` records for status, diagnostics or recovery. It leaves legacy records read-only. Looking up a missing session creates no directory or lock. A legacy `ended_at` value says the session ended once. A later prompt can still reopen it, so age alone cannot make it safe to migrate or clean up.

Session identities are validated before any directory is used: a missing or
empty id is refused rather than merged into one shared directory, and ids are
injectively encoded (allowed bytes pass through; every other UTF-8 byte
byte-for-byte ``~xx`` escapes, with a digest suffix for over-long ids). Reserved names and
Windows device names are rejected, a new directory whose name differs from a
sibling only by letter case is refused, and loading verifies that the
persisted session identity equals the event's identity before any write.
UUID-shaped ids map exactly as before.

## One writer and retained session data

All v2 writers acquire the same per-session kernel lock before creating,
loading or changing state. The lock stays at
`sessions-v2/.locks/<id>.lock`, outside the session directory. POSIX uses
`fcntl`; Windows uses `msvcrt`, with no third-party runtime dependency.
The lock covers the entire transaction. Process-local queuing and kernel
acquisition share one monotonic deadline; SessionEnd waits at most 1.2 seconds
for its current-session lock, further limited by a valid remaining Hook budget.
Descriptor/path identity checks harden commits, and a zero inode fails closed.
Identity checks do not provide a sandbox against arbitrary same-user mutation.

SessionEnd saves current state and, when active, recovery content. The separate
maintenance command reports its work as `cg-retention-report/v1`. It uses the
following checks:

- Preview is the default: `cleanup --data-dir <root>` scans, adjudicates and
  reports without touching session data. Without an explicit `--data-dir` the
  command refuses (exit 2) before resolving or creating any default home.
- Deletion requires an explicitly enabled retention policy
  (`cg-retention-policy/v1`; defaults: 30 days after session end, 7 days in
  recoverable quarantine, both clamped, purge enabled by default) plus an
  explicit apply using this pass's selection or a saved preview manifest.
  A policy object is never created automatically;
  a data root with no enabled policy stays preview-only.
- Eligible objects move to recoverable quarantine; `cleanup --restore <name>`
  puts one quarantined object back and refuses to overwrite a live successor.
  Permanent purge runs only after the quarantine grace period, is bounded and
  resumable, and leaves expiring tombstones; a purged object has no restore
  path and the messages say so.
- Every quarantine object has one record (`cg-retention-quarantine/v3`) whose
  state is written before the filesystem step it announces: `planned` before
  the move into quarantine, `restore_planned` before the move back,
  `purge_planned` before the first deletion. After an interruption the next
  pass (or the restore command) decides from the record state and the two
  directory positions: an unfinished move is rolled back or completed, an
  unprovable combination is reported as indeterminate and left alone.
  `purge_planned` is the point of no return: from then on the object is never
  offered for restore, and the record itself blocks a fresh ledger under the
  same session id until the tombstone replaces it.
- A restore moves an object back only after proving it is the complete object
  that left: the selection-bound creation identity, directory identity, the recorded `state.json` digest and
  a structural digest of every entry in the tree. A damaged or partially
  removed object stays in quarantine with the reason `content_mismatch`.
- Creation identity must be readable before every quarantine, restore and purge transition. A missing or unreadable creation time protects a new object before any move (`identity_unverifiable`). Earlier-candidate quarantine records bound only to change time or to nothing retain their object and name guard; they are not upgraded or restored by comparing directory layouts. Purge counts them under `purge_identity_unverifiable`.
- Destructive steps hold the maintenance lock and the original session's
  lifecycle lock. The maintenance lock is owned by one thread at a time (a
  second thread waits exactly like a second process; only true same-thread
  re-entry nests), and every wait for it consumes the caller's own deadline.
  Purge, like quarantine, is deferred (`purge_busy`) while a writer or reader
  of that session holds its lifecycle lock.
- Active, resumable, unfinished, busy-locked, partial-marker, legacy, linked
  and out-of-scope objects are protected with a named reason. Hooks create no
  maintenance object until maintenance is adopted. Discovery is durable
  across processes (plan D1): the session namespace and the quarantine
  directory each keep content-free hints under `.locks` -- a sorted,
  self-checking snapshot and an append-only journal whose records carry a
  CRC -- plus one versioned state file (`cg-retention-discovery/v1`).
  Enabling a policy lists both directories once and records that complete
  generation; every session this runtime creates appends its name after its
  directory exists, and maintenance journals each quarantine record and
  tombstone before writing it. Passes reach registered names in a stable
  sorted order after persisted window cursors, so registered work advances
  in every fresh process regardless of readdir order or directory size.
- Names no hint carries (sessions of older runtimes, lost or damaged hints)
  are found by a discovery generation: a names-only listing of both
  directories from their first entry, every entry charged to the pass
  budget. A generation runs when the hints or state are missing, damaged,
  torn or shrunk, when a directory's identity or modification time changed
  (or was sampled too close to the clock to be trusted), after eight
  invocations, or after an interrupted attempt. The first attempt uses half
  of the remaining budget; after a failed attempt the next one takes all of
  it. Capacity contract: when one listing of both directories plus its
  commit fits one invocation's budget (default 20 seconds), every unregistered
  name is reached after a bounded number of invocations. When a full-budget
  attempt still cannot finish, the report says `capacity_exceeded=true`,
  `backlog=true` and never `scan_complete`; later invocations give the
  registered windows the whole budget and retry the listing after a bounded
  backoff (at most every nine invocations), which clears the status once a
  listing completes. This is a fact about the budget and run conditions of
  that run, not a measured permanent limit; listing errors are reported
  separately. Unregistered names beyond capacity are not promised.
- Every enumeration charges the caller's deadline before each unit of work.
  Per-session lookups during resume and restore still list the quarantine
  directory filtered by name, bounded and refusing rather than guessing when
  cut; they are not indexed lookups. Purge removes each entry as soon as the
  listing yields it, so every budgeted pass makes durable progress on a
  registered quarantined object, and a purge cut by the budget keeps the
  window position for the next pass. The tree digest and hint parsing stop
  at the deadline.
- Quarantine, restore and purge re-check the record's directory identity
  after each intent is written, immediately before the move or deletion, and
  check the object actually moved or opened. A substituted object is left
  in place (or moved back) untouched, the transaction reports
  `identity_changed`, and an unprovable state stays indeterminate for
  inspection; purge never deletes a directory that is not the record's
  object. Each pass checks its deadline before every directory
  entry, adjudication and transition, and a transition cut by the deadline is
  queued for the next pass instead of being skipped. All 30 retired retention
  test nodes are individually mapped in
  `tests/retention_restoration_mapping.json`.
- Scheduled maintenance is opt-in: `cleanup --maintenance-enable` registers a
  daily job that runs the interpreter which executed the command with this
  exact script (launchd on macOS, a Task Scheduler definition on Windows) and
  loads or enables it; `--maintenance-status` reads back whether the
  definition exists, is current, and is actually loaded or enabled;
  `--maintenance-disable` unloads and removes it. An entry under the label
  that this data root cannot prove it owns is reported as foreign and is
  never overwritten, unloaded or deleted.

[Retention cleanup history](RETENTION_CLEANUP_FOLLOWUP.md) explains why
0.16.x disabled deletion. [Local acceptance](LOCAL_ACCEPTANCE.md) records
the subsequent source, native-platform and installation checks separately.

The private permission boundary remains mandatory for state and recovery
writes. A permission failure is still an error. Retention maintenance does not
make mandatory writes or synchronous filesystem calls preemptible, and the
complete installed SessionEnd command still needs its separate three-second
native timing gate. The lightweight entry's monotonic anchor and
current-session lock budget remain; no retention sweep runs after persistence.

The retired direct deletion helper stays refused, and there is no environment
switch that bypasses the preview/policy/manifest contract. Existing cursor,
pending chunks and registry objects are reused as progress data and discovery
hints only — never as deletion authorization. Partial markers for sessions
without a later state write keep protecting their object. After each
successful state write, the writer still attempts to retire its own old
partial marker under the lifecycle lock. A real successful resume also clears
`ended_at`, which keeps the session protected from maintenance. Old plugin
caches are immutable and keep their original behavior; this source change does
not update a running task's loaded runtime.

Do not use an older runtime's cleanup command, remove lifecycle locks, or
delete an active session as a substitute. Data removal outside this contract
still needs its own scope and recovery review.

Tests for deletion execution, interrupted progress and discovery fairness are
explicitly marked retired, with exact nodes, original source digests and previous
expected-failure status in `tests/retired_retention_cleanup.json`. The official
runner reports those nodes separately from passes and ordinary platform skips;
the old unregistered-tail expected failure is retained as a retired limitation,
not relabeled as passing. Current state, recovery, writer locks, identity,
private permissions, registry write boundaries and no-deletion controls remain
in the current suite. No 40-session assertion or timing budget was relaxed.
