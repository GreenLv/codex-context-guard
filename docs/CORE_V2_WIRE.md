# Core v2 wire candidate (provisional, unreleased)

Canonical owner: this repository. The planning contract is
[CORE_ALIGNMENT_CONTRACT_V2.md](CORE_ALIGNMENT_CONTRACT_V2.md). No installed
runtime or formal upstream pin is changed by this development identity.

## Inputs and identity

`core-observation/v2` is a pure projection input, not a model tool or an
execution permission. Only a host adapter builds its trusted event store.
Callers cannot establish trust by putting `trusted: true` in tool arguments.
Events have strictly increasing nonnegative safe-integer sequence numbers,
an immutable event ID, unit, revision, and a source kind. Projection takes an
explicit as-of sequence and current unit/revision. Events after that watermark
cannot affect an earlier decision. Root, host-call, host-result, final-delivery,
external-lifecycle and interpretation-candidate sources remain distinct.

A root source binds exact UTF-8 bytes and SHA-256. Coverage uses half-open UTF-8
byte intervals, including separators and unknown residue, with no overlap or
uncovered bytes. Endpoints must be Unicode scalar boundaries. The adapter
retains the source privately; public fixtures use synthetic text. Candidate
interpretations establish structure only: they cannot create facts or authority.

`core-state/v2` separates interpretation/coverage, delivery, effect, proof,
closure, ordinary interference, Stop and release. All IDs and target tuples
are exact case-sensitive strings unless a specific adapter normalizes a field.
Canonical JSON allows null, booleans, Unicode scalar strings, arrays, string-key
objects and safe integers only. Keys sort by UTF-8 bytes. No Unicode/newline
normalization, floats, duplicate keys, nonfinite numbers or implicit coercion.
Hash domain is `context-guard/core/v2` plus NUL; legacy digest-v3 and delivery-v1
bytes remain unchanged. Unknown fields fail schema validation.

Target origins carry `constraint_kind` (`exact`, `directory`, or `work_unit`)
and `selection_source_id`. Exact root targets must match exactly; directory
targets admit only a checked descendant. A `work_unit` choice preserves the
literal root scope phrase and byte span. Its selected target must come from a
same-unit/revision host call, with a correlated result and readiness fact at
or before the projection watermark. The host adapter first verifies that the
root asks for this kind of current action and contains no stronger exact or
directory restriction. Cwd, model text, and a bare selector cannot promote a
choice to root authority. These fields keep target provenance separate from
effect readback; neither selection nor readiness proves completion.

`target_origin.subject_kind` declares `filesystem` or `opaque`; it is not
inferred from a filename extension. A correlated host call also declares
`target_kind`, and its observed facts must match the requirement's kind and
the call's exact target. A Host result naming one suite or file cannot be
used as a readiness or effect fact for a different call target.
File edits, commits, pushes, and file-existence readiness require filesystem
identity. An opaque test-suite or measurement identity cannot be relabeled as
a file to bypass a root locator restriction, or vice versa. For a relative
exact file or directory, the immutable root source additionally
records its canonical `locator_base` and `locator_flavor`; the relative literal
remains byte-bound in `root_constraint_source`. `resolved_constraint` is required
for relative `exact`/`directory` and forbidden for absolute/work-unit choices.
The reference resolves a POSIX literal deterministically against that same
root base, rejects empty, dot, parent, home, variable, drive and UNC forms,
and requires resolution for every filesystem locator, including extensionless
names and long suffixes. One terminal slash on a relative directory is
normalized for resolution while the immutable literal span remains intact;
empty interior components remain invalid. The derived path must equal
`resolved_constraint`. An exact target
must equal it; a directory target must be a strict descendant, not a lexical
prefix sibling. Both require a correlated host selection/result at the same
unit, root revision and watermark. Non-root sources cannot carry a base.
Windows relative resolution is capability-unavailable in this provisional
reference; absolute Windows locator handling remains product-adapter scoped.
The adapter must obtain the base from the immutable prompt event, never the
latest cwd, and must fail closed on symlink or physical alias uncertainty.

A root prohibition is a required `constraint` requirement, distinct from a
positive execution requirement. Its `source` binds the prohibitive clause;
`target_origin.root_constraint_source` may bind a different span in the same
immutable root that names the forbidden target. A unique referent is an
adapter precondition; ambiguous antecedents remain `legacy_review`. For a
root-derived constraint, `implementation_choice`, `host_selection`, and
`observed` are null: absence of a Host call is not a fabricated observation.
Relative exact/directory constraints still require the root's original
`locator_base` and a deterministic `resolved_constraint`, but do not require
a Host selection just to remain active. A supported no-mutation constraint
uses `predicate: no_mutation`. A successful typed Host mutation is entered
as an `action_event` fact with `predicate: mutation_applied`, the forbidden
target, the constraint requirement ID and correlated call/result sources.
The core then projects `constraint_violated`; absent that fact it remains
`constraint_active`. Historical violations remain at later watermarks even
if an unrelated fact invalidates or succeeds; facts after an earlier Stop
cannot backfill it. Assistant reply text never creates a mutation fact.
The violating call must start after the immutable prohibitive root event;
a call timestamped before or at that root whose result arrives afterward has unresolved
causality (`constraint_unresolved`) and cannot certify, rather than being
retroactively counted as a violation or quietly treated as safe. The call,
result and fact must all be at or before the Stop watermark.
When a Host result arrives after a later root, its append sequence is only a
result-arrival bound. A host-call source may carry `origin_root_source_id`,
which must identify an earlier root in the same unit and Host turn. If that
origin precedes the prohibition, a result arriving afterward remains
`constraint_unresolved`; it cannot satisfy a later root requirement or prove
a later prohibition violation. Codex captures the turn identity in the
immutable prompt record and its hash. Missing, legacy or conflicting turn
identity stays unknown rather than being inferred from PostToolUse order.
The causal boundary is the immutable root source sequence, never a derived
requirement's insertion sequence: a requirement entered later cannot erase a
Host mutation that already followed its authoritative root.

## Current action basis

`current-action-basis/v1` binds unit/revision, root requirement/source span,
root scope digest, concrete action and target, an unmet predicate, owner,
ready inputs/conditions, and evidence watermark. A necessary substep names its
parent requirement and a checked relation (verification of the required change,
or readback of its required effect). A model-supplied relation is not sufficient:
the adapter must compare it with the live requirement's action and target.

Actionability requires the source and requirement to exist at the as-of
watermark; matching unit/revision/scope/target; a specific unmet predicate;
assistant ownership and verified readiness. Completed, future-observation,
capability-unavailable, evidence-insufficient, user-wait and external-wait are
separate diagnostic states. Generic legacy actions do not qualify. Reply
wording may nominate a candidate; it cannot register an external operation,
expand root scope, or change the event store. Lack of an action basis permits
ordinary ending without certification.

Explicit persistence and resume intent are distinct root-derived facts. Either
can request a continuation only with a valid current action basis. Wrong whole
completion and explicit proof violations are independent correction reasons.
All reasons share one correction per turn and an unchanged progress fingerprint
cannot loop. Root wait constraints remain constraints; registered external
operations additionally require a matching trusted lifecycle operation ID.
A later root instruction never changes an earlier Stop decision.

## State transitions and closure

Delivery is not_observed -> delivered only for a host final reply bound to the
current unit/turn and information span. Delivery proves occurrence, not truth.
Effect is not_observed -> success/partial/failure/unknown from matched host
call/result lineage. Process exit zero proves process result only. State-outcome
readback does not imply action-event history or unavailable prestate.
Proof is supported/unavailable/insufficient/satisfied/invalidated, by exact
predicate, source, target and current revision. Unknown residue and required
children block certification but do not block ordinary host tools or honest
ending. Constraints remain active without becoming pending actions. Goal
completion is checked only under an adopted completion contract.

Release uses existing adopted/reserved/consumed/unknown states and exact
product adapters. This core grants no ticket and never executes business work.
DSH's compatibility action/effect entries produce migration diagnostics without
ordinary side effects; its explicitly adopted registry surface retains all
pre-effect checks. Codex gains no business executor.

## Migration and evidence boundaries

Codex schema 13 and Stop 5.0.0 identify the new persisted Stop semantics;
execution/work-unit 3.0.0 and proof 1.0.0 keep their unchanged wire contracts.
Old decisions, certificates, journal and delivery identities remain historical.
New core projections rebuild only from available immutable sources and trusted
host observations. Old generic/qualification/text-wait records are never
promoted; unverifiable current terminal records become legacy review before
closure filtering. Repeated migration is idempotent and writes atomically.
Old runtimes must reject schema 13. Rollback requires the old state snapshot.

DSH assigns its new observation protocol independently; legacy digest-v3 and
formal UPSTREAM_PIN remain unchanged. The canonical source commit identifies
the exact ten shared files; the downstream mirror and formal pin need separate
verification before alignment is claimed. Verify all mirrors and rerun
cross-language/production comparisons before changing the formal pin. Local deterministic, synthetic host, real-model, native, artifact,
CI and release evidence are separate.

### P0 provenance details

Each source includes its actual host turn. Delivery matches the current turn;
late replies remain evidence of earlier delivery only. Each interpreted byte
interval must be represented by requirements/constraints; merely labeling a
source fully interpreted cannot omit its tail. Required children use their own
revision. Unknown or uncovered source bytes prevent certification.

The root target constraint includes a mandatory `root_constraint_source` span.
The reference checks its root origin, unit/revision, source digest and exact
UTF-8 text. A candidate cannot relabel its chosen target as a root constraint.
A literal directory constraint may contain an implementation-selected relative
descendant; path traversal is rejected. Nonliteral/anaphoric selection must be
resolved through the product's existing trusted selection chain before entering
this exact projection; unresolved selection remains insufficient. The other
identity layers remain distinct diagnostics and must agree at certification.

Intent recognizers are extracted unchanged from 0.13.9 into a versioned asset;
no added action vocabulary or user restatement template is required. Root span,
revision, quoted/code exclusion and actual action basis jointly constrain their
use. Interpreting intent still grants no ordinary execution permission.

DSH Goal completion adoption must be explicit and source-bound. Default opt-in
Guard activation may adopt the documented completion contract; installation or
an always-on observation profile alone cannot manufacture Goal adoption. The
DSH adapter must preserve actual earlier adoption facts, not infer them from
current enabled status. Goal scheduling and pause/restart remain host-owned.
