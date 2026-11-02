# Session retention cleanup: disabled gap and restoration conditions

Status: **deferred, disabled — not fixed, not re-enabled, not accepted.** The
0.16.0 release disabled session retention cleanup by an adopted scope
decision, and the 0.16.1 repair release keeps it disabled. Restoring cleanup
is a separate future version with its own versioned contract; nothing in
this repository re-enables it today.

## Current behavior and user impact

- SessionEnd saves current state and, when the guard is active, recovery
  content. No retention sweep runs at SessionEnd or anywhere else.
- The `cleanup` CLI command reports that it is unavailable and exits with
  code 2 before resolving or creating a data root. The internal
  `cleanup_old_sessions` API and the deletion helper reject the same way;
  there is no environment variable or fallback that re-enables deletion.
- Existing `sessions-v2` and legacy sessions, registries, cursors and
  pending chunk records are preserved. Successful state writes still retire
  the current session's stale partial marker inside the lifecycle lock, and
  a genuine resume clears `ended_at`. These narrow behaviors are not a
  restoration of bulk deletion.
- **User impact:** historical sessions stay on disk and storage can grow.
  There is no automatic 30-day deletion, no total storage cap, and no
  supported manual reclamation tool. Keeping the feature disabled is not a
  fix for storage growth.
- Do not work around this by invoking an older runtime's cleanup command,
  removing lifecycle locks, or manually deleting active sessions. Previously
  consumed plugin caches keep their own original behavior; disabling cleanup
  in this version says nothing about older installed runtimes.

## Retained historical record

`tests/retired_retention_cleanup.json` registers 30 retired test nodes
against baseline `1178b1426254654cff4ab84d1dd2dff33c6de3d6`, each with its
method digest, original expected-failure status and the replacement
disabled-cleanup control. Retirement means the corresponding deletion
executor is not enabled; it does not mean the old algorithm passed. One
original expected failure is retained verbatim:
`tests.test_cg0160_repair_family.RV03BoundedEnumeration.test_longer_decided_prefix_still_reaches_the_tail`
(fairness of reaching the tail under a long decided prefix). The other
retired nodes cover enumeration budgets, cursor and queue progress,
interrupted recovery, busy locks, ordering changes, registry and chunk
handling, partial deletion, identity and permissions; their historical
status is whatever each record says, not a blanket "known broken" list.

Source controls for the disabled state live in
`tests/test_retention_disabled_candidate.py`: SessionEnd save/restore, the
CLI and API early rejections, original-object preservation, permission and
identity handling, and marker handling.

## Design questions any restoration must answer first

These are requirements for a future cleanup version, not claims that each
item is broken today, and not authorization to implement anything now.

| Area | Question that must have a concrete answer and controls |
| --- | --- |
| Eligibility | Which state and age make a session deletable; how SessionEnd-but-resumable sessions are protected; how legacy, active-task and missing-provenance objects stay protected |
| Discovery completeness and fairness | How unregistered old directories, very long decided prefixes, concurrent directory changes, ordering changes and repeated short-budget scans are guaranteed to eventually reach the tail, with a reproducible progress invariant |
| Budgets | Enumeration and deletion must not crowd out mandatory state writes; a standalone maintenance entry point needs its own operation contract, not a larger SessionEnd timeout |
| Concurrency and identity | Writer/resume/cleanup races, busy locks, replaced objects, symlinks/reparse points/hardlinks, case aliases, Windows DACLs and held handles must fail closed |
| Recoverable deletion | Staged deletion, partial markers, crash/interruption, and disk or permission errors must resume without enlarging the deletion set or erasing the original failure |
| Metadata compatibility | Sessions that recorded no registry discovery while cleanup was disabled must be rediscovered safely; old cursor/pending/marker objects need an explicit retention and migration policy |
| Understandable bounds | The automatic and manual scopes, outputs, exit codes, any preview/retention period, and any restore path must be stated and implemented as promised |
| Old caches and upgrades | Consumed caches are never modified; new tools must not delete data an older runtime still depends on; cross-version states have explicit compatibility and rejection paths |

## Conditions for re-enabling cleanup in a future version

- A new versioned contract defines the deletion authority, object scope,
  retention and recovery policy; the old switch is not simply reopened.
- The retained expected failure demonstrates the new algorithm's correctness
  on its original risk, and every one of the 30 retired nodes is individually
  accounted for as restored, replaced, or not applicable, with review.
- Positive evidence shows complete multi-batch backlog processing; negative
  evidence shows active, resumable, busy-locked, unprovened and out-of-scope
  objects are not deleted; adversarial cases cover identity replacement and
  concurrency.
- Official readers re-open every should-keep fixture — with a controlled
  restart where needed — and still find saved state, recovery content and
  unfinished requirements; comparing directory counts is not acceptance.
- macOS and Windows each verify real filesystems, locks, permissions and
  process recovery natively; source doubles, CI, or the other platform do
  not substitute.
- Original observations of failures, interruptions and recoveries are
  retained; unknown, leftover or unowned cleanup stays unknown or failed.
- A selected performance contract completes, independently checking the
  full SessionEnd command timed from before spawn and natural exit; cleanup
  time is not excluded from the measured command.
- The canonical historical error library gate, upgrade and artifact
  acceptance, the privacy audit, and a release-documentation review pass
  before release preparation.

## Tracking

- Owner for the future cleanup-restoration work: **to be assigned**.
- Resume event: an independent cleanup-restoration version design is adopted.
- This page is the discoverable public entry point for the gap. It is
  linked from the session storage documentation, the documentation map and
  both READMEs; changelog and release notes for each affected version
  restate the user-visible bounds.
