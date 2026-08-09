# Versioning policy

Context Guard uses pre-1.0 semantic versioning as a product-contract signal,
not as a measure of code volume.

- `0.4.x` is the compatible correctness, security, Hook/API compatibility,
  test, and documentation line. It does not add a state schema, diagnostic
  interface, or cache-lifecycle guarantee.
- `0.5.0` establishes schema 4, classifier 1.0.0, bounded hash-only Stop
  diagnostics, and durable historical Hook cache archives with audited repair.
- `0.5.x` contains compatible fixes inside those contracts. Installed cache
  bytes are immutable: a runtime byte change requires a new patch version.
- Requirement-to-evidence semantic relevance is not a 0.5.0 capability. It is
  a possible `0.6.0` only after a benchmark covers positive, negative,
  adversarial, multilingual, false-acceptance, and abstention cases.

The project may declare 1.0 only after the public Hook, state, diagnostics,
installer, recovery, compatibility, and deprecation policies are stable;
schema migration and historical-cache recovery have native acceptance on every
supported platform; Stop benchmarks and privacy thresholds have operational
evidence across at least two minor series; sibling shared-core parity is a
maintained gate; and rollback behavior lets already-open tasks finish safely.

Version numbers do not prove that successful evidence is semantically relevant
to a requirement. Current checkpoints prove provenance and tool outcome only.
