# Next candidate: independent review R2

Reviewed source: `f8d74ac7ab753b8d42b4d3caa96fdd6e6f700a3a` (2026-10-02).
Scope: the existing R1 families F1–F4, including lock subdesign revision 2.
Decision: **namespace separation is accepted as the design direction; the
proposed migration protocol is not approved for implementation.** F2 and F4
also remain open. This is not a new candidate freeze or a request for another
complete test matrix.

## F1: separation is useful; the migration exclusion proof fails (P1)

Separate `sessions-v2` and legacy state, a central path resolver and fail-closed
unsupported file identity are appropriate. However, revision 2 sections 2.2,
2.4 and 4 do not establish the claimed invariant:

1. Checking absence and then calling `O_CREAT` is not exclusive creation. The
   old writer can create its lock between those operations. A coordinator probe
   used the actual baseline runtime to enter the critical section in that gap;
   the proposed migrator then opened the same file and acquired its kernel lock.
   Both were inside. Using `O_EXCL` for the migration claim would close this one
   schedule, but does not resolve the next one.
2. Five seconds of waiting does not bound the age of a migration marker. A
   migrator can pause, copy a large tree, or be suspended for over 30 seconds.
   A newly arriving legacy process then unlinks the aged marker immediately,
   before its own deadline matters. Holding the new kernel lock does not stop
   this. An isolated probe aged the marker to model this suspension and observed
   the real baseline process enter while the migrator retained its kernel lock.
   Periodically refreshing mtime or checking the deadline cannot eliminate
   suspension between the last check and source consumption/publication.
3. A crash after creating the stable legacy marker leaves a file that section
   2.1 rejects forever. The claimed next-event retry therefore cannot happen.
   Staging cleanup based on age or PID absence is likewise not proof of exclusive
   ownership of a still-running migrator's directory.
4. Absence of a per-event lock is not session quiescence. The old host may be
   alive between Hook calls and later introduce new requirements. Automatic
   migration on first write is not an explicit ownership transfer; creating
   two histories for one continuing task needs a deliberate transition contract.
5. Copying with `symlinks=True` can preserve aliases into mutable legacy data or
   outside the state root. A directory name alone does not prove isolation.
   Define rejection or safe materialization for links, junctions/reparse points
   and other unsupported entries. New cleanup must not delete legacy-owned
   state or another migrator's staging. Exclude `.lock` and transient ownership
   records from the imported state; validate the exact persisted file inventory.
6. Moving an inode check next to `os.replace` does not eliminate its race. Do
   not claim that the second check proves no commit after arbitrary replacement.
   Prove that supported product writers and cleanup cannot perform that
   replacement, and retain the check only as diagnostic hardening. Truly
   external tampering can be a stated threat-model exclusion, not a passing
   result for a deliberately injected post-check replacement.

### Concrete scope decision for the next design

Remove automatic online migration and the 30-second marker proof. New sessions
may use v2; an existing legacy session must stay usable with its old immutable
runtime, while a new runtime refuses to mutate or silently replace that history.
Read-only fallback must not repair corruption, create prompt records, or perform
cleanup in the legacy tree.

Design migration as a separate explicit operation with a demonstrably quiescent
source, or consume an immutable, validated export produced under a supported
quiescence procedure. Specify who establishes and maintains quiescence for the
entire source read and ownership transfer, how failure blocks publication, and
how recovery obtains the same authority. A user-facing claim that a lock was
absent, a PID scan, or a hash comparison is not that proof. If this release
cannot implement such a procedure, explicitly leave migration unsupported;
preserve old sessions on their old runtime and document the upgrade/resume
boundary. Do not silently weaken the frozen preservation contract.

The next bounded design review must choose one feasible path, address restart
at every crash point and cross-namespace cleanup, and distinguish newly created
sessions from upgraded/resumed ones. No co-located locking patch is requested.

## F2: an unknown size must refuse admission (P2)

The two original long-key probes are fixed. The replacement estimator is not
conservative: `_bounded_size_estimate` returns 8 at excessive depth and adds
only 8 for all elements after the first 64. The full original object is retained.
Production `EvaluationContext.store_basis` probes found:

| Shape | Budget | Charged | Retained payload |
| --- | ---: | ---: | ---: |
| Dictionary with a large value after entry 64 | 4,096 | 1,778 | 1,000,000 bytes |
| Eight nested dictionaries around a large value | 4,096 | 274 | 1,000,000 bytes |

These are admission counterexamples, not claims about their frequency in current
Stop traffic. The accepted input API has no shape rejection preventing them.
At a traversal limit, cycle, unsupported type or exhausted counting budget,
return an explicit unknown/over-budget result and bypass retention. Never
undercount the unvisited suffix. Bound estimator work cumulatively, not merely
per container; avoid a huge temporary UTF-8 encoding solely to reject an entry.

Close the whole family in one repair: retained keys and values, parsed fragment
objects as well as two text views, search matches and containers, the accounting
tables themselves, and mutation after admission. Either own immutable snapshots
or document and enforce how retained mutable values cannot grow outside the
budget. Repeated-key replacement must not accumulate phantom charges or leave
unrefunded capacity after phase clearing. Phase-local projections bounded only
by an arbitrarily large journal are not an aggregate byte bound; provide a
separate finite cap or prove that they retain references without extra copies
and state the exact excluded baseline memory.

Do not add one constant for each new counterexample. Define one admission rule,
then cover width/depth limits, unknown shapes, mixed families, lazy views and
phase transitions, with unchanged direct-evaluation verdicts.

## F3: incomplete exception accepted; enforcement remains open (P2)

The coordinator accepts `CGI-20260913-codex-archive-045` as an incomplete-original-
chain exception on the available canonical record: the trigger cannot be
faithfully reconstructed. Keep its bounded-diagnosis/invalid-control test as
generic evidence, never as proof of the missing original chain. New original
evidence reopens this exception. This accepts the substantive exception; it
does not independently certify every entry in `sources_checked`.

The warm-resolver Windows waiver withdrawal is accepted. Its applicable Codex
analogue remains pending native evidence; this is not a DSH certification task.
The new final-head execution receipt and the preservation of old Windows
runtime identities are appropriate evidence boundaries.

The exception validator only looks up exceptions when a row's free-text missing
evidence contains a marker. A negative probe retained the 045 exception fixture,
removed that marker, and changed all results and its verdict to `executed_pass`:
`validate_rows` reported no errors. Thus the claimed exception cross-check can
be bypassed by the very pass conversion it should prevent.

Join exceptions and coverage by exact case ID independently of prose markers.
Require unique entries, a matching active case, typed review status and an
explicit excluded-incomplete result that cannot count as a pass. Check both
directions, cross-case references, missing markers and orphan/duplicate entries.
Represent the accepted review without requiring `coordinator_review=required`
forever. The release gate may close only when all applicable non-exempt cases
pass and every incomplete exception is approved and separately counted; generic
`pending` or other missing-platform rows must still block it.

## F4: driver self-test does not yet establish a reliable gate (P2)

Raw event rows, wrapper loading and active session seeding improve the driver.
The following defects in `tools/validation/perf_ab.py` remain in the same
measurement family and must close before the formal batch:

- `main` returns zero regardless of execution or semantic failures. Summary
  latency excludes failed/time-out attempts and includes semantic failures in
  the `completed` distribution. A sample of one 1-second success and one
  10-second timeout reports median/p95/max of 1 second. Retain raw observations,
  but make success-conditioned statistics explicit and prevent a censored or
  failed batch from satisfying the all-attempt acceptance rule.
- `nearest_rank([1,2,3,4],95)` returns 3, not 4. Use `ceil(n*p/100)-1` and test
  non-integral ranks. The command-line timeout is unused by the event calls.
- The loop executes all baseline attempts before all candidate attempts, despite
  claiming interleaved A/B. Predeclare an interleaved order and record it.
- Missing baseline identity support substitutes the candidate runtime digest
  into the baseline field. Record unavailable identity and block formal use, or
  calculate the actual baseline tree with the same explicitly versioned hasher.
- Seed timeouts, unexpected driver errors and assertion exceptions can abort
  before writing the report. Persist each started attempt incrementally,
  preserve partial output on failure and do not overwrite an existing result.
- Lifecycle recording discards each event's output/timing/identity and ignores
  the `expect` values. It asserts only aggregate counts, not pair attribution
  or content, and runs five pairs rather than the planned 100-event cell.
  Add per-event semantic oracles, actual event-wrapper binding, matched tool
  identities and the requested workload size. Include fixture/seed identity.
- Four available cells alone do not cover the planned nine events, Stop cases
  and memory measures. Define the finite union with existing benchmark runners
  and required identities; do not claim one driver implements the entire matrix.

Add driver negative tests for a no-op Hook, malformed output, child failure,
semantic failure, timeout, seed failure, absent identity and interrupted output.
Self-test those cheaply; defer formal timing until F1/F2 converge.

## Evidence and next handback

The coordinator independently ran 52 evaluation/coverage-negative-control tests:
all passed. Isolated production-method probes and a modeled migration schedule
nevertheless reproduced the findings above. The migration probes exercise the
proposed steps against the actual baseline writer; there is no implemented v2
migrator to certify. Product runtime bytes were not edited during this review.

Next owner: the development executor returns the revised F1 design first and
repairs independent F2/F3/F4 paths in parallel within the same batch. The
coordinator resumes on that design and then the repaired source handback.
Retain F1/F2 family failures and formal performance/full historical/native/model/
CI/publication gates as pending. Keep unrelated accepted behavior closed.
No additional full matrix, daily HOME installation, tag or Release is requested.
