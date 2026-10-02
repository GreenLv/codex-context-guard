# Next candidate: independent review R3 and implementation decision

Subject: `e926f91be44e46259723ef35a9c34ef75bbd8cff`, 2026-10-02.
Scope remains F1–F4. No release candidate is frozen.

## F1 decision: implement isolation without migration in this release

Revision 3's premise is false: `ended_at` is a recorded event, not an enforced
terminal state. The coordinator executed the actual baseline runtime at
`d24899d` through two prompts, SessionEnd, and another UserPromptSubmit on the
same session. The final prompt succeeded, prompt count grew from 2 to 3, and
the persisted state changed while `ended_at` remained set. Dispatch has no
terminal-state write rejection. SessionEnd itself saves `ended_at` before its
subsequent recovery write and cleanup. Thus even observing that timestamp
does not prove that the ending invocation has finished writing.

This is a supported product entry-point counterexample, not hostile external
tampering. No verified host contract makes those later writes impossible.
The same false premise invalidates the proposed lock-inode proof for cleanup:
an ended, old session can still have a writer or be resumed.

The coordinator makes the following bounded implementation decision, replacing
revision 3 sections 2–4 where they conflict:

1. **No legacy migration in this release.** Do not implement
   `migrate-legacy-session`, online copying, ended-only copying, or automatic
   import on first write. Keep migration as unsupported future work, requiring
   an independently enforceable quiescence/immutable-source contract. This is
   the explicit unsupported-migration option already allowed by R2.
2. Use `sessions-v2` for genuinely new sessions. Preserve legacy trees and
   consumed runtime caches. Old sessions continue with their old runtime;
   the new runtime must not silently replace them with empty state. Document
   the unsupported upgrade/resume boundary and a verified way to continue the
   old task. Do not promise that keeping cache bytes alone pins a host's loaded
   runtime: installation/native acceptance must prove the continuation path.
3. New-runtime legacy access is strictly read-only. No corruption repair,
   prompt creation, implicit recovery save, migration marker or legacy cleanup.
   Ordinary business tools retain their existing approval-free path. Unknown
   or explicitly adopted release posture remains fail-closed. A Stop handling
   unavailable legacy verification must not certify completion or silently
   discard unresolved requirements; return a bounded actionable diagnostic.
   A warning plus disabled completion protection is not an accepted substitute.
4. Prove v2 cleanup exclusion structurally. Use a stable per-session lifecycle
   lock outside the deletable session subtree, acquired by every v2 writer
   before resolving/creating/loading state and by cleanup before checking and
   deleting. Re-read eligibility under that lock. Do not delete/recreate this
   lock as part of session cleanup. Alternatively omit destructive automatic
   v2 cleanup for this release with an explicit documented retention boundary.
   Choose one of these two bounded paths in the implementation handback.
5. Keep the one-session writer invariant, total bounded lock wait, stdlib-only
   runtime and platform-aware termination. `st_ino==0` stays fail-closed. An
   inode check is hardening, not the exclusion proof. Cover all supported
   writers, CLI commands and cleanup through the same lifecycle protocol.

### Adjudication of revision 3 section 3.4

The coordinator accepts that this version need not support hot migration or
automatic adoption of old sessions. The proposed ended-only migration and
the proposed weakening of N09 are **not accepted**. N09's preservation rule
remains unchanged; no migrations occur in this release. Existing unfinished
requirements stay with the preserved old runtime/state. Old-session
continuation and the new-runtime refusal behavior are required acceptance
cases, not an undocumented compatibility gap.

This narrowed design is approved for implementation within these boundaries;
no fourth design-only handback is required unless implementation reveals a
contradiction or needs a materially different contract. Update the subdesign,
plan, compatibility text and tests together, retaining the rejected proposals
as historical rationale rather than active instructions.

## F2: admission must cover every route before allocating copies (P2)

The width/depth estimator now refuses unknown suffixes, and the two R2 large
value probes no longer retain their payload. Two remaining family defects were
independently reproduced:

- `store_basis` performs `copy.deepcopy` before the bounded estimator. A
  1-byte-budget context given a 1,200-level nested value raises `RecursionError`
  instead of bypassing caching. Oversized supported objects also incur the
  full copy before being rejected. Measure/validate the supported graph before
  copying, bound the copy operation itself and preserve direct-evaluation
  behavior on rejected shapes. Do not rely on catching every exception after
  an unbounded allocation.
- The new 32 MiB cap only controls `disk_prompt_records`. The alternate
  `_read_prompt_record` → `root_records`/`prompt_records` route still retains
  full records without accounting. With text budget zero and projection cap
  one byte, an isolated prompt-reader mock returning a one-million-byte record
  left that record in `_prompt_record_memo`, charged zero. The mock isolates
  admission; it does not claim a live journal observation.

Finish the single inventory of retained storage required by R1/R2. Apply the
projection cap to the aggregate of all projection entry paths, rather than
one accessor. Include parsed fragments, lazy views, match/container storage,
accounting tables and mutable retained projections in the conservative
accounting rule. The state's already-loaded baseline objects may be explicitly
excluded only where the cache retains references rather than unaccounted
copies. Preserve source-consumption integrity when declining caches. Convert
both probes into bounded-admission regressions and test the production callers;
do not treat fixing only the latest two payloads as family closure.

## F3: retain the current correction

Exact-ID exception association, typed row linkage, approved 045
`excluded_incomplete`, separate exclusion counts and the remaining warm-resolver
Windows pending row match the R2 decision. The relevant negative-control tests
pass. Retain this family as closed for the reviewed fixture and association
changes; the full historical release gate still requires its outstanding
platform evidence and a fresh/reusably bound complete inventory.

This acceptance is not native Windows evidence, DSH certification, or a claim
that every future malformed exception schema is covered.

## F4: required cells are silently omitted (P2)

An actual CLI probe ran `--formal --attempts 20 --cells memory_stop,stop_s1`
against the candidate. It exited zero and produced `accepted=true` with
`cells={}`. `main` filters selected names through `cell_specs`, but neither
special cell is registered there. Their branches are unreachable. Default
formal use therefore also silently omits them. Unknown cell names have the
same empty-success behavior.

Use one authoritative registry for normal and special cells. Reject unknown,
empty or duplicate selections; validate positive attempt counts and enforce
the required formal profile. A subset diagnostic may be useful, but cannot
claim completion of the full performance gate. At finalization require exact
agreement among planned cells, started attempts, terminal outcomes and recorded
results. An interrupted or absent attempt must remain visibly incomplete and
block acceptance.

Close the special-cell integration, not only its selection branch: run the
actual Stop runner with its supported CLI, validate its output schema and exit
code, and establish a semantic oracle for the memory Stop result. The current
memory helper labels any returned decision `assertion=ok`. Record input/fixture
and hasher identities as well as runtime identity. Run one cheap diagnostic
through every registered cell after repair; no need for formal timing now.

The lifecycle oracle still checks evidence count without verifying its command,
outcome and pair identity. A wrong record can satisfy that count. Complete the
required association oracle and a negative test for a wrong-command record.
Use each event's actual wrapper and declared host deadline (SessionEnd's
3-second budget must not become the global default 10 seconds). Preserve each
started attempt before seeding/execution so interruption leaves an identified
incomplete row. Dispose of the driver's owned temporary homes after evidence
is saved; `mkdtemp` per attempt currently has no cleanup.

Retain the fixes already made for nonzero failure exits, explicit
success-conditioned statistics, nearest-rank calculation and interleaved
ordinary cells. Formal speed/memory acceptance remains pending.

## Evidence and next owner

The coordinator ran 74 focused evaluation, incident-coverage and performance-
driver tests: all passed. Separate isolated probes demonstrated the four
counterexamples above. Product code was not changed during this review.
Only review documentation was added; documentation checks are separate from
runtime acceptance.

The developer may now implement the narrowed F1 scope and complete F2/F4,
retaining F3 and unrelated accepted behavior. Return one bounded family
handback with source identity and positive/negative production-path evidence.
After family convergence, run the formal performance/full source checks once,
then hand back for independent integrated review before native/model/full-CI
and publication work. No migration or release approval is implied by this
implementation decision.
