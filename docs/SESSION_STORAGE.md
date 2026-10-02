# Session storage and upgrades

New 0.15.0 sessions use `sessions-v2/<id>` beneath the private plugin data root.
Existing `sessions/<id>` trees and consumed versioned plugin caches remain with
their original runtime. There is no migration command, automatic import or
legacy cleanup in this version.

Here, HOME means the Codex configuration and task-data directory selected by
`CODEX_HOME`, not the operating system user directory.

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

For concurrent old and new work, install from the new source checkout with
`python scripts/manage_plugin.py --codex-home <new-home> --apply`, replacing
`<new-home>` with a fresh private directory. Start that Codex process with
`CODEX_HOME` set to the same directory. Keep the old task in its original HOME
with the old plugin selected. Each HOME has its own login and normal Hook trust
setup; selecting a different HOME does not transfer tasks or their ledgers.

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

## One writer and safe cleanup

All v2 writers and cleanup acquire the same per-session kernel lock before
creating, loading or changing state. The lock is stored at
`sessions-v2/.locks/<id>.lock`, outside the deletable session directory. It is
never unlinked by release or cleanup. POSIX uses `fcntl`; Windows uses
`msvcrt`, with no third-party runtime dependency.

The lock covers the entire transaction. Process-local queuing and kernel
acquisition share one monotonic deadline; SessionEnd has a 1.2-second lock
budget within its three-second Hook deadline. Descriptor/path identity checks
harden commits, and a zero inode fails closed. Identity checks do not replace
kernel exclusion or provide a sandbox against arbitrary same-user mutation.

Cleanup scans only v2, acquires that same lock, then rereads state and retention
eligibility before deleting the session subtree. It leaves the lifecycle lock
in place. Contention skips cleanup within the budget; a queued writer proceeds
only after release. Resumed v2 activity clears the old retention timestamp.
Legacy trees and their timestamps are unchanged.

`test_session_namespace` covers routing, read-only legacy access, ordinary-tool
and release boundaries, cleanup and resumed activity. `test_session_lock_protocol`
uses real processes and barriers for contention, aged live locks, process death,
commit ownership and old/new namespace isolation. Native platform and actual
loaded-host results are recorded separately from those source tests.
