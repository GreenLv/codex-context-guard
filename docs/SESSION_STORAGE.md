# Session storage and upgrades

New 0.15.0 sessions use `sessions-v2/<id>` beneath the private plugin data root.
Existing `sessions/<id>` trees and consumed versioned plugin caches remain with
their original runtime. There is no migration command, automatic import or
legacy cleanup in this version.

Here, HOME means the Codex configuration and task-data directory selected by
`CODEX_HOME`, not the operating system user directory. Since the 0.16.0
release line, direct commands without an explicit data root resolve their private
state under the active `CODEX_HOME` (`<home>/context-guard`), so isolated
homes never share state; with `CODEX_HOME` unset the historical default is
unchanged. The same directory also carries the optional existing
`interpreter.conf` (one absolute interpreter path) that the Hook launchers
consult on GUI hosts whose PATH lacks the installed Python; the launchers re-verify it on every start. The marketplace-only version
does not create this file; GUI Python discovery still needs verification.

Session identities are validated before any directory is used: a missing or
empty id is refused rather than merged into one shared directory, and ids are
injectively encoded (allowed bytes pass through; every other UTF-8 byte
byte-for-byte ``~xx`` escapes, with a digest suffix for over-long ids). Reserved names and
Windows device names are rejected, a new directory whose name differs from a
sibling only by letter case is refused, and loading verifies that the
persisted session identity equals the event's identity before any write.
UUID-shaped ids map exactly as before.

## Continue existing work

Keep the old task's original cache and session data. Continue it under the
original loaded runtime, and check the actual Hook source path and identity.
Keeping a directory on disk does not prove that the host loaded that version.
Codex CLI 0.158.0 on Windows was observed switching an existing task to the
new Hook on its next turn after an in-place plugin upgrade, even while the
original host process remained alive. Finish old tasks before changing that
HOME's selected plugin, or keep a separate HOME explicitly configured for the
original version while new work uses a fresh HOME. Do not copy Hook trust or
session data into the new HOME; review its Hooks normally. A fresh task can use
the new version independently. Cold-resuming an arbitrary old task through a
newly selected runtime does not import its ledger.
See [compatibility](COMPATIBILITY.md) for the supported boundary and
[local acceptance](LOCAL_ACCEPTANCE.md) for observed host routes.

The marketplace-only version proposes a distinct market identity for new
work. It has not established old-task continuation, independent enable/disable
or strict no-op preservation through official installation. A second HOME is
not proof of task or trust transfer. Keep old objects and daily configuration
unchanged until the relevant native acceptance is complete. See
[the installer removal record](INSTALLER_REMOVAL.md).

The new runtime resolves existing v2 state first, then legacy state; only a
new session creates a v2 directory. Its legacy access is strictly read-only:
no repair, new prompt, recovery write, migration marker or cleanup. Status,
diagnose and recovery-page can read old records; write commands refuse them.
An absent-session read creates no directory or lock. Ordinary business tools
keep the approval-free path. Unverifiable completion or explicitly adopted
release evidence cannot be certified; Stop and PreCompact return bounded
instructions for continuing with the original runtime.

A legacy `ended_at` value records SessionEnd, not an irreversible terminal
state. The old runtime accepts later prompts and may still write after that
field is saved. File age, lock absence, an old marker or time between Hooks
therefore cannot establish a safe migration window. A future migration needs
an enforceable quiescence and immutable-source contract.

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

SessionEnd saves current state and, when active, recovery content. Session retention deletion is disabled: automatic sweeps do not run, and the `cleanup` command reports that it is unavailable with exit code 2 without deleting data. Existing v2 and legacy sessions remain on disk, so storage can grow; there is no automatic 30-day deletion or storage cap. This version provides no supported manual reclamation tool. Keep active tasks, session data, lifecycle locks and existing plugin caches intact.

The private permission boundary remains mandatory for state and recovery
writes. A permission failure is still an error. Disabling retention work does
not make mandatory writes or synchronous filesystem calls preemptible, and the
complete installed command still needs its separate three-second native timing
gate. The lightweight entry's monotonic anchor and current-session lock budget
remain; no retention sweep runs after persistence.

The `cleanup` command rejects the request before resolving or creating a data
root. `cleanup_old_sessions` and the internal deletion helper also report
unavailability before accessing the supplied path. There is no environment
switch or fallback that re-enables deletion. Existing cursor, pending chunks and registry stay on disk, as do partial
markers for sessions without a later state write. State saves no longer append new
discovery entries while retention cleanup is disabled; existing registry bytes
and objects are preserved. After each successful state write, the writer still
attempts to retire its own old partial marker under the lifecycle lock. A real
successful resume also clears `ended_at`. Old plugin caches are immutable and keep their original behavior; this
source change does not update a running task's loaded runtime.

Do not use an older runtime's cleanup command, remove lifecycle locks, or delete
an active session as a substitute. A separately requested data-removal operation
needs its own scope and recovery review; this version supplies no safe bulk
reclamation procedure.

Tests for deletion execution, interrupted progress and discovery fairness are
explicitly marked retired, with exact nodes, original source digests and previous
expected-failure status in `tests/retired_retention_cleanup.json`. The official
runner reports those nodes separately from passes and ordinary platform skips;
the old unregistered-tail expected failure is retained as a retired limitation,
not relabeled as passing. Current state, recovery, writer locks, identity,
private permissions, registry write boundaries and no-deletion controls remain
in the current suite. No 40-session assertion or timing budget was relaxed.
