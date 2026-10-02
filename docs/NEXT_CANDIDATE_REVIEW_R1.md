# Next candidate: independent review R1

Reviewed source: `99c89556abf35e3a1493feebdf0605f31f44d43d`, against
`d24899d8202a58d7426208541c58d193464e93de` (2026-10-02).
Decision: **not ready for candidate freeze or native release acceptance**.
The normative development plan remains in force. Lock subdesign A is rejected;
subdesign B is not implicitly approved by this decision.

## Review boundary and retained evidence

This review covers the changed lock, evaluation memo, Hook delegation,
instruction discovery, supersession, release classification, associated tests,
and the historical/performance handback. It is a bounded candidate review, not
a claim that every possible architecture defect has been excluded.

The coordinator independently ran 56 tests in the session-lock,
evaluation-context, phase-2 and default-path modules: all passed. Separate
isolated macOS probes using the actual baseline writer and candidate APIs
nevertheless reproduced the contradictions below. No daily installation,
shared live state, remote branch, tag or Release was changed. The developer's
full suite and isolated-install receipts remain developer evidence; they do
not establish closure of these additional counterexamples.

Review lenses are authority, writer identity, state transitions, resource bounds,
platform feasibility and evidence identity. P1 means a reproducible violation
of a correctness invariant; P2 means a required resource/evidence contract is
unclosed. Both must be resolved for this release. Recheck these families and
affected callers after repair; do not restart unrelated review or run the full
matrix after each individual example.

## F1: exclusive writer and migration (P1)

Owning code: `filesystem_session_lock`, `SessionLockGuard.verify_ownership`,
`save_state` in `scripts/context_guard.py`; `docs/LOCK_SUBDESIGN_NEXT.md`.

**CGR-L1: a live legacy holder is still admitted concurrently.** The candidate
accepts legacy records aged at least 30 seconds. In an isolated test the actual
baseline process remained alive inside its lock while the candidate entered
and saved state. The two locks referred to the same inode, so the new inode
check could not distinguish their ownership. A second schedule paused the
baseline between exclusive creation of the empty file and writing its owner
record: the candidate accepted the empty record and both writers entered and
saved. Missing or malformed ownership is not evidence of absence of a writer.

**CGR-L2: the commit check has a check-to-write race.** A deterministic pause
after the candidate's ownership check, immediately before its actual atomic
write, allowed the baseline process to replace the aged lock and save valid
state. Resuming the candidate overwrote that state and returned successfully.
A subsequent ownership check detected the changed inode, too late. Atomic
replacement prevents torn JSON, not lost updates or overlapping writers.
`verify_ownership` also returns success when an inode is zero; an unsupported
identity primitive must not silently certify ownership.

Required invariant: at most one writer for the same private state, across
supported versions and all mutation paths. A dispossessed writer cannot commit
success or remove a successor's lock. Repeated `stat` checks cannot enforce the
write boundary against an old writer which ignores the new lock primitive.

Repair the protocol/migration design before implementing another local patch.
Provide a feasible proof that old and new writers cannot reach the same mutable
state concurrently. If isolation is chosen, specify namespace selection,
existing-session resume, migration quiescence, authoritative state identity,
rollback and rejection behavior; silently starting empty history is forbidden.
Do not rely on an unread marker, a new lock filename, record age, or a PID alone.
Submit this concrete design for the already required bounded coordinator review.

Close the family with actual baseline and new writers in both directions:
new/new contention; old/new contention; live holders older than the timeout;
empty/partial/malformed owner records; takeover before and after ownership
checks; crash/termination during acquisition and each persisted transition;
queue deadline; successor cleanup; unsupported identity primitives. Audit all
state, release-latch, action-profile, recovery and prompt-record writes for the
same isolation boundary. Assert final state consistency and no lost updates,
not only process markers. Replace the test that expects aged legacy takeover.
Make termination tests platform-aware (`SIGKILL` is not a portable Windows API).
Native `msvcrt` semantics remain a later Windows gate.

## F2: aggregate evaluation memo budget (P2)

Owning code: `EvaluationContext` and `_ParsedText` in
`scripts/context_guard.py`. CGN-02 remains open.

**CGR-M1:** with a one-byte budget, an action-source lookup returning no matches
retained a 100,008-byte source string in its tuple key while charging zero bytes.
With a 64-byte budget, a negative basis result retained a key containing that
same string while charging only 64 bytes for the value. These use public class
methods, not direct mutation of the cache dictionaries.

Use one documented conservative accounting rule for retained keys, values,
containers and lazy derived views. Inventory every memo, including parsed text,
clauses, action sources, search results, negative basis results, scope, disk,
root, prompt and control projections. For any excluded storage, explicitly
bound its lifetime and size and explain why it is outside the contract. Avoid
allocating an unbounded serialized value just to compute its cost. Define how
phase clearing releases accounted capacity. Direct fallback must preserve
verdicts after admission is refused.

Tests must cover long keys with empty/negative values, many small entries,
derived-view growth, multilingual strings, repeated phases and mixed memo
families sharing a small budget. Compare admitted and bypassed evaluations,
including production Stop callers. Existing positive accounting tests and the
original retained-text reproducer are necessary but insufficient.

## F3: historical verdict and subject identity (P2)

The current library inventory has 53 active cases (45 registry and 8 legacy).
The developer's 62 executed nodes are useful source-test evidence, not proof
that every historical trigger and platform has passed for this candidate.

The execution receipt is bound to `2f574e411cb1e47d7e586b6458c9d9becc5a4edf`,
not the reported final head. The subsequent review-document-only change may
permit reuse: retain the original subject and prove unchanged gate inputs.
Do not relabel a reused run as an execution on the final head.

Coverage rows still contain Windows passes from the prior 0.14.3 runtime
digest. Preserve them as historical evidence and evaluate invalidation by
changed inputs; they cannot certify new lock/router bytes. Keep current native
requirements pending where affected. The full historical gate must appear in
the handoff's pending list until applicable execution, adjudication and
candidate identity agree.

Two explicit adjudications remain:

- `CGI-20260928-dsh-warm-resolver-scope-drift`: its canonical record contains a
  Windows failure as well as macOS observations. Origin-platform metadata alone
  does not justify `windows_result=not_required`. Define and test the applicable
  Codex freshness analogue on required platforms, or document a substantive
  product-specific non-applicability argument. No DSH product certification is
  requested from this repository.
- `CGI-20260913-codex-archive-045`: the canonical diagnosis says the original
  Hook, syntax, timing and wrapper are unknown. The current test proves bounded
  direct diagnosis and rejection of an invalid private control, but does not
  reproduce that unknown historical rejection chain. Seek a sufficient oracle;
  otherwise record a reviewed incomplete-case exception with missing fields and
  retained generic regression evidence. Do not count the exception as a pass.

Refresh the full inventory and lineage before release. Use the user's existing
exception for genuinely incomplete cases; unknown results, timeouts and missing
platform runs are not automatically incomplete cases. Preserve unrelated
historical-library working files.

## F4: performance measurement and handback claims (P2)

The supplied entry A/B JSON stores aggregate summaries without raw attempt
records or immutable driver/input identities. Its driver counts only process
exit status, discards output semantics and lets a timeout abort the batch before
recording the attempt. The 100-event diagnostic alternates Pre and Post across
ten session IDs such that each session gets only one event kind; it is not a
matched active tool lifecycle. It invokes the shell launcher, not the exact
configured Hook wrapper. The four repeated 100-event batches were correctly
described as diagnostic in the limitations, but cannot close the formal gate.

Retain the reported Post/UserPrompt speedups and Stop S1 results as scoped
diagnostics. The SAFE entry median/p95 increased in the supplied summaries;
use the planned absolute/relative tolerance rather than calling any small
baseline an automatic pass. Do not present output byte reductions as measured
token savings or real-model effectiveness.

Repair the driver first: matched active sessions and event identities, assertions
on output and persisted semantics, exact production-wrapper identity, raw samples,
timeouts/failures retained without replacement, input/driver/source digests and
the planned percentile calculation. Cover the planned event, lifecycle, Stop
and memory cells. Use at least 20 predeclared attempts per formal cell. Run the
formal batch once after F1/F2 converge; do not spend native/model slots now.
List formal performance as pending in the handoff until then.

Align the Skill/instruction map with `checkpoint-status --commands`: default
status does not emit all advanced commands. Keep deterministic instruction-byte
results separate from pending GPT-6 model acceptance.

## Required next handback and stop rule

1. Return the concrete F1 isolation/migration design for bounded review before
   integration. No version contract is frozen by this review; retain 0.15.0 as
   the planning target until that design is settled.
2. Implement the accepted design and close F1/F2 with a shared-cause explanation,
   entry-point matrix, positive and adversarial production-path tests. Correct
   F3/F4 evidence and documentation in the same bounded repair batch.
3. Return exact source identity, changed paths, focused results and a structured
   handoff that retains missing gates. Keep current candidate bytes confined to
   fresh isolated homes; never overwrite consumed 0.14.3 caches.
4. The coordinator independently replays the open families. Once source and
   reader documents converge, select the new version, run the complete source
   and historical gates, and freeze one candidate for exact full CI/HOL and
   macOS/Windows native, installation and GPT-6 acceptance.
5. Publication remains pending all required gates. Follow the repository's
   annotated-tag and bilingual Release sequence with public readback.

No new full-matrix or native run is requested merely to answer this review.
Accepted unrelated behavior stays closed unless new evidence or an affected
dependency reopens it. The development executor owns the repair; the coordinator
resumes on the concrete lock design, then the repaired candidate handback.
