# Versioning policy

Context Guard uses pre-1.0 semantic versioning as a product-contract signal,
not as a measure of code volume.

- `0.4.x` is the compatible correctness, security, Hook/API compatibility,
  test, and documentation line. It does not add a state schema, diagnostic
  interface, or cache-lifecycle guarantee.
- `0.5.0` establishes schema 4, classifier 1.0.0, bounded hash-only Stop
  diagnostics, and durable historical Hook cache archives with audited repair.
- `0.5.1` keeps schema 4 and the existing decision interface while applying
  classifier 1.0.1 ownership fixes, derived-state normalization, and a
  fail-closed same-version archive-adoption path.
- `0.5.x` contains compatible fixes inside those contracts. Installed cache
  bytes are immutable: a runtime byte change requires a new patch version.
- `0.6.0` is a protocol-first turn-control minor. Schema 5 adds a private,
  turn-bound disposition protocol with `continue`, `user_wait`,
  `external_wait`, `deferred`, and checkpoint-derived `complete`. It reuses
  `UserPromptSubmit`, `PostToolUse`, and `Stop`; it does not add a Hook event,
  matcher, or Codex payload field. Classifier 2.0.0 is diagnostic except for
  narrow whole-task completion and explicit user-persistence safeguards. The
  0.6.0 candidate was installed but never released: a real Code Mode raw-stdout
  run could not prove success from its bare private marker, so the version is
  consumed and its cache remains immutable.
- `0.6.1` is a compatible receipt patch. A successful private checkpoint or
  disposition precheck now prints a final standalone `Script completed` after
  its exact hash marker. The bare marker remains rejected, and structured
  failure, nonzero status, or hard failure text takes priority. Schema 5, Stop
  protocol 1.0.0, classifier 2.0.0, the four dispositions, Stop priority, and
  the eight-Hook wire are unchanged.
- `0.6.x` contains compatible fixes inside schema 5 and Stop protocol 1.0.0.
  Installed cache bytes remain immutable: a runtime byte change requires a new
  patch version.
- Requirement-to-evidence semantic relevance is not a 0.6.x capability. It is
  a possible `0.7.0` only after an approved benchmark covers positive,
  negative, adversarial, multilingual, false-acceptance, false-rejection, and
  abstention cases.

The project may declare 1.0 only after the public Hook, state, diagnostics,
installer, recovery, compatibility, and deprecation policies are stable;
schema migration and historical-cache recovery have native acceptance on every
supported platform; Stop benchmarks and privacy thresholds have operational
evidence across at least two minor series; sibling shared-core parity is a
maintained gate; and rollback behavior lets already-open tasks finish safely.

Version numbers do not prove that successful evidence is semantically relevant
to a requirement. Current checkpoints prove provenance and tool outcome only.
