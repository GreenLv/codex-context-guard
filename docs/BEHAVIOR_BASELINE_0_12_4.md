# 0.12.4 behavior baseline (source candidate)

Status: **unreleased source candidate** for `0.12.4` (private state schema 11,
Stop protocol 3.0.0, classifier 3.2.1, Proof 1.0.0, Execution 2.0.0, nine Hook
events, Python 3.10+ standard-library runtime). This document is the current
behavior baseline required by the 0.12.2 stabilization plan and carried through
the consumed 0.12.3 trial into the 0.12.4 repair candidate. It states what the
candidate is implemented and regression-tested to do at the source boundary,
which parts depend on a real host, and which evidence is still missing. Native statements below describe only the recorded scenarios and platforms; this baseline does not grant a release claim.

Evidence boundary: P1, CG122-08 and P2 source acceptance retain their original prepared-source identities. The recorded product runtime has passed portable acceptance independently on macOS and Windows, plus separately reviewed six-gate macOS and Windows real-host composites. The local, uncommitted tools/documentation successor has a separate passing source suite; the preceding tools suites retain their original tool/test identities. The runtime tree is unchanged, while this successor differs from the 107-file prepared product source. Local evidence reconciliation and exact-byte reader review cover the revised documents; whole P4/P5 closure, final artifact/full-source parity, exact-main CI/HOL and publication remain pending. The [acceptance record](LOCAL_ACCEPTANCE.md) owns exact counts, identities and reuse boundaries.

## Historical alignment ledger

The v0.9.4 delta ledger (`docs/upstream-deltas.json`, ledger version 1, source
v0.9.4 / schema 7 / Stop protocol 2.0.0) and the v1 conformance fixtures are a
**historical alignment snapshot** of the earlier cross-host alignment round.
They are preserved unchanged as frozen history; they do not describe current
0.12.4 capability, and historical v1 fixture or Stop-protocol-2 semantics must
not be read back as today's behavior. Current behavior is defined by the
sections below plus the current-behavior suite; DSH still adapts from this
repository, and unported 0.12.4 behavior remains pending/deferred on the DSH
side until separately accepted there.

## Behavior areas

For each area: the expected behavior, where it lives (implementation and
regressions), what depends on a real host, which native evidence is missing,
and what DSH would have to adapt later.

### 1. Requirement recovery across compact/resume

- **Expected.** A follow-up instruction keeps the unfinished task and its
  original limits. Quoted examples, plan tables, and topic switches do not move
  current limits into history. Operational correction wording does not ask
  which requirement to replace unless the correction itself names a
  requirement-like target; an actual unresolved correction remains
  fail-closed. Recovery serves the current projection first:
  complete text is delivered in pages bound to the requested session
  (`recovery-page/v1`, `--session-id` required), long requirements keep their
  suffix constraints, and a changed scope invalidates old page cursors.
  100+ historical items cannot crowd out current obligations.
- **Locator.** `scripts/context_guard.py` recovery projection and the
  `recovery-page` subcommand; regressions in
  `tests/test_cg122_p1_state_recovery.py`, the supersession counterexamples in
  `tests/test_cg122_p0_counterexamples.py`, and
  `tests/test_context_guard_phase3.py`.
- **Host dependency.** Real PreCompact/SessionStart dispatch, compaction
  timing, and session identity come from the host; source tests use synthetic
  Hook payloads.
- **Native evidence and remaining scope.** The recorded macOS and Windows `compact_resume` gates pass with actual PreCompact, compact-start SessionStart, and consumed recovery state in their original sessions. Other resume paths remain pending.
- **DSH later adaptation.** The same current-first projection, paging, and
  session binding would need porting; nothing here authorizes a DSH change.

### 2. False whole-completion prevention and Stop subjects

- **Expected.** Ending a child task, external job, or local phase never claims
  completion of the current task. One shared bounded interpretation classifies
  the Stop-completion subject (current work unit, subordinate/external
  operation, local phase, other/unknown), scope (whole/partial), speech act,
  and remaining-action owner. Only an affirmative current-unit WHOLE completion
  claim invokes whole-completion evidence derivation; quoted, reported,
  hypothetical, negated, and interrogative wording never triggers it. Unknown
  subjects never auto-complete a unit. A real whole completion stays gated even
  next to an unrelated wait sentence.
- **Locator.** `classify_stop_decision` and `claims_whole_completion` in
  `scripts/context_guard.py`; regressions in
  `tests/test_cg122_stop_subject.py` and
  `tests/test_cg122_p0_counterexamples.py`.
- **Host dependency.** Actual Stop/UserPromptSubmit decisions are host turns;
  synthetic tests replay payload shapes only.
- **Native evidence and remaining scope.** The macOS and Windows `continuity_wait` gates pass for their recorded wait/Stop/release sequences. This does not provide native coverage for every Stop-subject regression.
- **DSH later adaptation.** The typed subject/scope/speech-act model and the
  CG122-08 incident family would need a DSH-side port.

### 3. Evidence binding and completion proofs

- **Expected.** Completion requires evidence that proves the requested
  operation. A paired direct-tool commit result or a unique complete local
  readback can bind a commit; failed commits, scope mismatch, base drift, and
  ambiguous candidates have distinct failure reasons. Forged text, bare SHAs,
  and model summaries are not evidence. Weak evidence never proves a stronger
  obligation.
- **Locator.** Evidence and proof paths in `scripts/context_guard.py`
  (Proof 1.0.0 facts, digest v3 bindings) plus
  `tests/test_cg122_p2_binding.py` and
  `tests/test_context_guard_phase4.py` completion families.
- **Host dependency.** Tool-result pairing depends on the host's real
  tool_call/tool_result records. The observed inner Bash `tool_use_id` is distinct from the outer wrapper id, and its Post response is an opaque string, not a typed exit code.
- **Native evidence and remaining scope.** The macOS and Windows `commit_event` and `local_push_readback` gates pass for recorded exact Bash commands with paired Hook events and independent Git readback. Unobserved wrapper shapes remain pending.
- **DSH later adaptation.** Digest v3 is shared and frozen; DSH already mirrors
  the fixture, but the 0.12.4 commit/readback binding behaviors are not ported.

### 4. Authorization scope and profiles

- **Expected.** The default profile checks that a covered high-risk action was
  authorized by the root user for the current work unit; a later unrelated
  prompt cannot extend an authorization to another repository or target.
  Release-grade obligations (readiness contract, one-shot ticket) stay on the
  release profile; `observe` only records. Ordinary prose, product
  explanations, and test instructions never create authority.
- **Locator.** `scripts/cg_actions.py` command classification and
  `observe_push_target`/`resolve_internal_targets` in
  `scripts/context_guard.py`; regressions in
  `tests/test_context_guard_phase4.py` and the authorization families of
  `tests/test_context_guard.py`.
- **Host dependency.** PreToolUse dispatch, real command lines, and repository
  identity come from the host.
- **Native evidence and remaining scope.** The macOS custom run recorded unauthorized, wrong-ref and stale-SHA denials. These bounded canaries are separate from the six-gate composites and do not cover every authorization surface; Windows authorization canaries remain separately unverified.
- **DSH later adaptation.** The profile ladder is Codex-specific; DSH keeps its
  native scheduling and would adapt the authorization-generations model.

### 5. Typed waits and one-shot release

- **Expected.** A confirmation releases only the matching pause. Waits are
  typed (`one_shot`, `migrated_unresolved`, external/session-restricted forms)
  and carry source and subject hashes; "the model is ready" does not clear a
  separate file-check pause; unrelated replies, unmet conditions, and ambiguous
  confirmations keep waiting. A uniquely bound `SubagentStop` fact can end only
  that child's wait. Schema 11 never rolls back lossily to schema 10.
- **Locator.** `validate_wait_conditions` and the wait-condition kinds in
  `scripts/context_guard.py`; schema in `assets/state.schema.json`; regressions
  in `tests/test_cg122_p1_repair.py` and `tests/test_context_guard_phase3.py`.
- **Host dependency.** Real confirmations and subagent lifecycle events arrive
  through host Hook events.
- **Native evidence and remaining scope.** The macOS and Windows matching wait/release sequences pass with their original raw prompt and state witnesses. Other external producers and subagent-lifecycle variants remain separately unverified.
- **DSH later adaptation.** Typed waits plus the no-lossy-rollback rule would
  need porting; schema 7/8 remain read-only inputs on both sides.

### 6. Source-ready commit identity

- **Expected.** Commit-and-push follows the authorized source objects only:
  the root user's affirmative file scope, or uniquely attributable
  current-task edits when no files were named. Exclusions, read/test
  references, quoted material, and untouched objects add no files; unresolved
  explicit ceilings fail closed. Permission to do further fixes is separate
  from preparation: readiness turns true only after verified edits made under
  the current authorization generation. The complete commit must match the
  frozen parent, paths, modes, and blobs; extra or missing paths deny.
- **Locator.** `scripts/cg_commit.py` tree/index comparison and the scope and
  preparation regressions in `tests/test_cg122_p2_scope_timing.py`.
- **Host dependency.** Real git operations and the host's nested tool-call
  layer; source tests perform local fixture commits only.
- **Native evidence and remaining scope.** The macOS and Windows `commit_event` gates pass for their recorded direct Bash command-Hook pairs and exact commit readbacks. Unobserved nested shapes remain pending.
- **DSH later adaptation.** Commit semantics are Codex/git-shaped; DSH has no
  equivalent surface today, so this stays deferred there.

### 7. Push target confirmation

- **Expected.** A clear push request is not padded with a redundant
  restatement request: a unique target resolved from a direct tool invocation
  is remembered as a still-current fact, and one later root push confirmation
  can use it. The target fact alone grants no permission; stale, ambiguous,
  or unrelated targets are asked again, and force-push, deletion, and release
  actions keep their separate authorizations. “Push the current candidate
  commit” names an existing Git object rather than authorizing a new commit.
  A statement-named full SHA is retained exactly, succeeds only when it
  matches the live repository HEAD, and otherwise denies as drift.
- **Locator.** `observe_push_target` and the authorization snapshot targets in
  `scripts/context_guard.py`; Skill guidance in
  `skills/context-guard/SKILL.md`; regressions in the authorization families
  of `tests/test_context_guard.py`, `tests/test_context_guard_phase4.py`,
  and `tests/test_cg122_p4_live_reauthorization.py`.
- **Host dependency.** Real remote state and actual push execution stay
  host-side and network-side.
- **Native evidence and remaining scope.** The macOS and Windows `local_push_readback` gates pass against their local bare remotes. These are not GitHub or publication results; arbitrary named-remote variants remain outside this evidence.
- **DSH later adaptation.** Not applicable today; DSH has no git push surface.

### 8. CG122-08 completion subject and remaining-action owner

- **Expected.** When a subordinate operation ends while the root still waits
  for user data, an external result, a readback, or acceptance, the turn
  boundary is allowed only as the existing typed wait; no proof registration
  happens for an unmade whole-completion claim. Result-unavailable and
  missing-attachment states preserve root obligations. Mixed clauses resolve by
  subject and relation, not by the latest keyword; at most one visible
  correction per turn; compact/resume keeps pending and the correction budget.
- **Locator.** The shared Stop-subject interpretation in
  `scripts/context_guard.py` (`classify_stop_decision`,
  `claims_whole_completion`, waiting-owner facts); regressions in
  `tests/test_cg122_stop_subject.py` (synthetic Chinese/English variations,
  mixed clauses, repeated Stop, compact/resume).
- **Host dependency.** Actual Stop-hook decisions and wait condition state in
  a real session.
- **Native evidence and remaining scope.** The macOS and Windows `continuity_wait` gates observe their recorded Stop/wait scenarios. They do not establish every mixed-clause or child-completion variant.
- **DSH later adaptation.** The Windows-incident family that motivated this
  behavior is DSH-side history; DSH would adopt the subject/relation model as
  a separately accepted change.

## What the baseline does not claim

- `legacy_fallback` remains the visible boundary for deterministic
  verification the runtime cannot perform; the guard is not a security
  sandbox, an arbitrary semantic verifier, or a universal completion oracle.
- Source-suite passes do not imply installed, native-platform, real-host, CI,
  or release evidence. Each stays a separate recorded fact.
- The `host_behavior` profile can accept only evidence supported by a reviewed raw mapping and validator. Each accepted macOS and Windows composite replays its two original partial results under their pinned tools, then combines complementary gates for one product subject and platform. Generic or serialized capture summaries remain non-authoritative; missing evidence stays pending and contradictions fail. The explicit offline archive-view mode requires stopped writers and restores the original directory before accepting replay; it preserves raw bytes and child identities. Shared platform/version text does not establish shared executable bytes. Full results remain private, and the composites have no public annex. Neither establishes whole P4/P5 completion or removes the historical R3 executable-evidence limit.
- The historical v1 conformance fixtures, the schema-10 parked fixture, and
  the frozen transition audit keep their original bytes and meaning as
  history; they are not reinterpreted as current capability.
- DSH alignment beyond the frozen digest-v3/conformance mirrors is pending
  work in the DSH repository, not a property claimed here.
