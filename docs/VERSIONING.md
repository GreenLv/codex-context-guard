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
- `0.6.2` is a one-way-safety correction inside schema 5. Stop protocol 1.1.0
  keeps the four-value wire contract but makes legacy `continue` advisory;
  only verified whole-task completion and hash-verified explicit persistence
  can request a correction turn. Quote-aware, shell-tool-scoped intent parsing
  prevents documentation and pure-search text from being mistaken for private
  control execution. Classifier 2.0.0 and the eight-Hook wire remain unchanged.
  A real candidate installation consumed this version before the final manager
  lifecycle bytes were frozen; it remains immutable, untagged, and unreleased.
- `0.6.3` carries the same schema-5 runtime and Stop protocol 1.1.0 policy while
  hardening cache lifecycle transactions. Indexed live drift is repaired before
  unindexed versions are adopted, and legacy archive Git metadata is removed
  only when the trusted product manifest matches before and after cleanup.
- `0.6.x` contains compatible fixes inside schema 5 and the Stop 1.x protocol
  line.
  Installed cache bytes remain immutable: a runtime byte change requires a new
  patch version.
- `0.7.0` introduces schema 6 and Proof protocol 1.0.0. Deterministic
  verification contracts bind successful evidence to required subjects,
  surfaces, visual readbacks, and normalized scope sets. Hash-only multimodal
  asset contracts retain metadata and visual facts without persisting image
  bytes. Unsupported cases are visibly `legacy_fallback` and keep the 0.6.3
  checkpoint behavior. Stop protocol 1.1.0, classifier 2.0.0, and the eight-Hook
  wire remain unchanged.
- `0.7.1` keeps the 0.7.0 schema and protocol contracts unchanged and
  reconciles late transcript attachment metadata before the first tool
  evidence. Native fresh-task acceptance consumed 0.7.0 before exposing this
  defect, so its cache remains immutable.
- `0.7.x` contains compatible fixes inside schema 6 and Proof protocol 1.x.
  Installed cache bytes remain immutable: a runtime-byte change requires a new
  patch version.

The project may declare 1.0 only after the public Hook, state, diagnostics,
installer, recovery, compatibility, and deprecation policies are stable;
schema migration and historical-cache recovery have native acceptance on every
supported platform; Stop benchmarks and privacy thresholds have operational
evidence across at least two minor series; sibling shared-core parity is a
maintained gate; and rollback behavior lets already-open tasks finish safely.

Proof protocol 1.0.0 guarantees only the deterministic obligations displayed
for an `enforced` item. It does not claim arbitrary pixel understanding,
official-source validity, or semantic completeness for `legacy_fallback` items.
