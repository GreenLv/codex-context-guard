# Protocol-authoritative completion

Status: proposed design target for 0.9; not implemented by the 0.8.x runtime.

## Objective

Version 0.9 should make authenticated protocol state authoritative for task
completion. Only a valid, turn-bound structured checkpoint that covers every
non-superseded requirement and acceptance item may transition a task to
`complete`.

This removes natural-language completion classification from the completion
state-transition path. It is intended to eliminate the class of false
continuations caused by quoted, hypothetical, example, attributed, translated,
or otherwise incorrect completion wording. Natural-language analysis may still
be wrong, but that error must not change protocol state or force another turn.

## Normative contract

1. `complete` is derived only from an authenticated structured checkpoint. It
   is not a disposition and cannot be asserted by assistant prose.
2. `user_wait`, `external_wait`, and `deferred` end the current turn while
   preserving unresolved items as pending. They never imply completion.
3. Assistant prose, quotations, examples, classifier labels, and an erroneous
   statement such as "the task is complete" cannot change task state and cannot
   independently force continuation.
4. When no valid structured control is staged, Stop yields safely and preserves
   unresolved items. Absence of a control is not completion and is not an
   automatic continuation request.
5. Private-state integrity failures, forged or replayed controls, invalid or
   incomplete checkpoints, and prompt-boundary ambiguity remain fail-closed.
6. An explicit, authoritative user request to keep working remains a hard gate
   on terminal yield until work continues or a genuine unavailable boundary is
   established. It does not itself mark the task complete.
7. Natural-language classification is diagnostic only. It may support
   telemetry, explanations, warnings, and debugging, but it has no authority
   over completion, continuation, or pending-item state.

## Decision model

At a Stop boundary, the runtime should evaluate protocol inputs rather than
assistant wording:

1. validate private-state integrity and the current prompt/turn binding;
2. authenticate and validate the single staged structured control, if present;
3. derive `complete` only from a checkpoint that closes the entire active
   requirement and acceptance set;
4. otherwise honor a valid wait or deferred boundary while retaining pending
   items;
5. enforce an explicit user persistence request unless a genuine unavailable
   boundary applies; and
6. if none of the above requests another action, yield safely with unresolved
   state preserved.

The natural-language classifier runs outside this decision model. Its output is
observability data, not an input to the state transition.

## Security and authority boundaries

The design does not make arbitrary tool output authoritative. Checkpoints and
dispositions must remain private, turn-bound, hash-bound, single-slot controls
staged only through the authenticated Hook path. A malformed, stale, leaked,
replayed, or conflicting control must not weaken the completion gate.

User authority remains distinct from assistant language. A root-user request to
continue may constrain terminal yield, while an assistant sentence discussing
or claiming completion has no protocol authority.

## Compatibility and migration

The 0.8.x Stop protocol still lets a narrow high-confidence natural-language
completion classifier participate in a hard gate. Version 0.9 should remove
that dependency as a deliberate protocol change rather than accumulating more
phrase-level exemptions.

Migration should preserve pending requirements, evidence, proof obligations,
and safe wait/deferred boundaries. It must discard or re-authenticate in-flight
controls so that an older task cannot authorize a new completion transition.
Already-open tasks must keep using their immutable trusted runtime and remain
safe during rollback.

## Acceptance gates for 0.9

The 0.9 implementation is acceptable only when all of the following hold:

- a task can reach `complete` only through a valid full-coverage checkpoint;
- direct, quoted, hypothetical, attributed, translated, and adversarial
  completion prose produces identical protocol state when structured controls
  are identical;
- wait and deferred controls yield with unresolved items preserved;
- no-control Stop safely yields without inventing completion or continuation;
- invalid, forged, replayed, stale, conflicting, and partial checkpoints fail
  closed;
- explicit user persistence remains effective without giving assistant prose
  control authority;
- diagnostics clearly distinguish classifier observations from protocol
  decisions;
- native macOS and Windows fresh-task tests validate installation, Hook trust,
  persistence, rollback, and historical-cache behavior.

## Relationship to 1.0

Protocol-authoritative completion is an appropriate 0.9 design objective. It
should become a prerequisite for 1.0, not a claim that 0.9 alone stabilizes the
entire product. A 1.0 declaration additionally requires stable public Hook,
state, diagnostics, installer, migration, recovery, compatibility, privacy,
and deprecation contracts, plus operational evidence across supported native
platforms and more than one minor series.

This design can eliminate natural-language completion false positives from the
completion decision path. It cannot guarantee that diagnostic language models
never misclassify text, that tools never report incorrect facts, or that all
future protocol implementations are bug-free; those errors are contained so
they do not become completion authority.
