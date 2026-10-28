# Session storage and upgrades

New 0.15.0 sessions use `sessions-v2/<id>` beneath the private plugin data root.
Existing `sessions/<id>` trees and consumed versioned plugin caches remain with
their original runtime. There is no migration command, automatic import or
legacy cleanup in this version.

Here, HOME means the Codex configuration and task-data directory selected by
`CODEX_HOME`, not the operating system user directory. Since the 0.16.0
candidate, direct commands without an explicit data root resolve their private
state under the active `CODEX_HOME` (`<home>/context-guard`), so isolated
homes never share state; with `CODEX_HOME` unset the historical default is
unchanged. The same directory also carries the installer-written
`interpreter.conf` (one absolute interpreter path) that the Hook launchers
consult on GUI hosts whose PATH lacks the installed Python; each HOME binds
its own interpreter and the launchers re-verify it on every start.

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

Cleanup scans only v2, acquires that same lock without blocking, then rereads
state and retention eligibility before deleting the session subtree. It leaves
the lifecycle lock in place. Contention skips cleanup within the budget; a
queued writer proceeds only after release. Resumed v2 activity clears the old
retention timestamp. Legacy trees and their timestamps are unchanged.

Since the 0.16.0 candidate the sweep is bounded inside the SessionEnd host
budget, with budget, persisted progress and fairness as separate mechanisms.
The registry design is adopted with the unregistered-directory limitation
stated below. Enumeration is deadline-bounded per read, as
originally required: every readdir step starts only within the remaining
budget, an already-expired budget requests nothing, and there is no
queue-cap truncation — the batch is bounded by the deadline and sorted only
after the read phase ends, so a pass with ample budget reads the whole
namespace regardless of readdir order. The lexical resumption cursor is
persisted only when its scan reached the end of the namespace (every name
at or below it was then actually read and decided, so skipping them later is
sound even when readdir order is not lexical); an interrupted scan persists
the pending queue with an empty cursor and the next pass re-reads the
namespace without skipping anything, re-adjudicating decided names at
bounded cost rather than risking an unread name.

Discovery has a second, order-free source: a durable discovered-session
registry of content-free encoded names, written by the session save path
when a v2 session is created and extended by every name the sweep reads
(so even a deadline-interrupted scan persists its discoveries
position-free). The registry is a hint, never an authority: entries are
component-gated on read, re-verified against the live namespace object at
adjudication (real directory, not a link, still present), and compacted to
the live namespace when a generation completes. A missing, truncated or
corrupted registry falls back to the deadline-bounded backfill sweep at
bounded cost. Names read but left undecided are persisted in a content-free
pending queue as fixed-size chunk files with an index — the producer's
write domain equals the reader's read domain, so a legitimate queue can
never be refused by its own reader, and each chunk is validated
independently so one corrupted chunk costs only its own names. The queue
drains before any new sweep and the drain's decisions are not re-queued by
the same pass's own sweep. The queue and the registry are progress data,
not a scope grant: the legacy namespace stays read-only. A pass that drains
the queue and reads the namespace to its end resets the generation so order
changes and recreated names are re-decided. An interrupted deletion leaves
a content-free marker so the next pass finishes it without re-deriving
eligibility, and running out of budget returns safely with the remaining
backlog in the queue for later passes. Directory links are unlinked without
following them. A successful later write for a marked session — a real
resume — retires the marker inside the same lifecycle lock, so historical
cleanup eligibility can never delete a live session. Current-session
persistence always runs before the sweep.

The registry design is accepted for registered-session discovery. Existing,
never-registered directories remain supported, but repeated small budgets and
adversarial directory order can leave tail entries undiscovered indefinitely.
There is no bounded discovery-delay guarantee for that shape, including after
registry loss until backfill actually discovers the entries. The known model
counterexample remains an expected failure, not a passed original assertion.
Registered sessions make fair progress in the finite model; real platform and
host observations retain their own evidence boundaries. UserPromptSubmit events are never collapsed: repeated
(session, turn, prompt-bytes) shapes are recorded only as a bounded,
text-free diagnostic observation, because the hook payload carries no
per-message identity.

`test_session_namespace` covers routing, read-only legacy access, ordinary-tool
and release boundaries, cleanup and resumed activity. `test_session_lock_protocol`
uses real processes and barriers for contention, aged live locks, process death,
commit ownership and old/new namespace isolation. Native platform and actual
loaded-host results are recorded separately from those source tests.
