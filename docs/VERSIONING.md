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
- `0.7.2` hardens compatibility after a differential 0.6.3 versus 0.7.1
  audit. Private controls require execution of the current runtime; complete
  scope enforcement requires a prompt-derived expected count or exact object
  set; `PostToolUse` performs at most one transcript scan per pending prompt
  while compaction/resume remain forced retries; and recovery clipping reserves
  the completion rule. Schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0,
  classifier 2.0.0, and the eight-Hook wire remain unchanged.
- `0.7.3` requires an affirmative mutation clause before enforcing visual
  result readback and gives an unambiguous prompt-explicit scope count
  precedence over attachment count. Denied or out-of-scope mutation wording
  remains inspection-only. The consumed 0.7.2 cache remains immutable; schema
  and all protocol versions are unchanged.
- `0.7.4` keeps schema 6, Proof protocol 1.0.0, and Stop protocol 1.1.0 while
  advancing the diagnostic classifier to 2.1.0. Whole-completion gating now
  requires a current-task assertion instead of treating object complements,
  hypotheticals, attributed quotations, or framed examples as the assistant's
  own completion claim. Remaining-action extraction also excludes negated
  topical mentions such as “configuration tutorial” from future assistant work.
- `0.7.5` keeps the 0.7.4 protocol and classifier versions while constraining
  negation to the latest explicit assistant-future segment. A denied action
  before “but I will ...” no longer hides the later authorized action, and
  action verbs such as “review documentation” remain actionable rather than
  being discarded as nominal topic mentions. The 0.7.4 cache remains immutable.
- `0.7.6` keeps the 0.7.5 protocol and Hook surface while advancing the
  diagnostic classifier to 2.2.0. Whole-completion gating recognizes plural and
  quantified claims and explicit first-person reporting, and ignores questions,
  trailing negations, attributed speech, and hypothetical completions. The Hook
  entry fails closed on Python older than 3.10. The 0.7.5 cache remains
  immutable.
- `0.7.7` keeps schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0, and the
  eight-Hook wire while advancing classifier metadata to 2.2.1. Subject
  discovery rejects slash-delimited prose and URL path fragments, recognizes
  bounded `codex://threads/...` locators, and avoids inferring a UI surface from
  generic Chinese apply wording. A valid structured `view_image` image data URL
  is successful visual evidence while explicit failures remain authoritative.
  The consumed 0.7.6 cache remains immutable.
- `0.7.8` is a consumed compatibility candidate. It advanced the classifier to
  2.2.2 but was installed before the exact `Plan updated` receipt and required
  regression fixtures were complete. Its cache remains immutable.
- `0.7.9` completes the compatibility fixes and advances the classifier to
  2.3.0. Real `update_plan` string receipts can update the read-only plan
  mirror; Stop privacy uses bounded control-text categories without retaining
  sensitive values; and visual receipts accept legacy data-URL objects and
  desktop `input_image` content blocks. It adds no execution authority.
- `0.7.x` contains compatible fixes inside schema 6 and Proof protocol 1.x.
  Installed cache bytes remain immutable: a runtime-byte change requires a new
  patch version.
- `0.8.0` is the consumed intermediate schema-7 Phase 2 candidate. It was
  installed before its state-schema contract was complete and remains
  immutable.
- `0.8.1` is the first completed Phase 2 candidate. Schema 7 and execution
  protocol 1.0.0 add a dormant, canonical-hash-bound model for instruction
  sources, contracts, phases, gates, authorization candidates, drift, exact
  host coverage, ticket namespaces, unified-exec sessions, and delegated actor
  bindings. Schema 6 migrates without losing durable evidence; dormant schema
  7 can project back for rollback reading, while a non-dormant ledger refuses a
  lossy downgrade. No contract is activated and no authority is granted.
- `0.8.2` is a consumed intermediate Phase 3 package identity. Its installed
  bytes remain immutable; it was neither tagged nor released.
- `0.8.3` is the first completed Phase 3 release and the first release that can
  adopt reviewed project instructions and an optional Codex Plan binding. It
  keeps the source roles separate: the root
  user defines task and write authority; `AGENTS.md` and Skills define workflow;
  Codex Plan remains revisable; and tool, file, image, UI, or public readback
  provides facts rather than authority. The root-user-only `context-guard adopt
  <project-relative-json>` control accepts a bounded, hash-only deterministic
  contract. A changed Skill or plan marks the affected binding for review
  without modifying Codex Plan. Status, diagnosis, and recovery expose only
  bounded IDs, counts, states, and hashes. The release does not add
  `PreToolUse`, block tools, reserve tickets, commit, publish, or grant authority
  to uncovered surfaces.
- `0.8.4` keeps every 0.8.3 schema, protocol, classifier, and Hook contract
  unchanged while hardening installation and cache lifecycle. The marketplace
  is registered at a sanitized, manifest-verified staging copy instead of the
  immutable Git checkout; an existing checkout registration migrates only
  under managed `--apply`, while non-apply diagnosis remains read-only and
  actionable. Already-affected live caches are repaired from their trusted
  archives without overwriting consumed versions or deleting private state.
- `0.8.5` corrects commit-addressed consumer upgrades.
  Version 0.8.4 recognized only the current checkout or staging path, while a
  pinned consumer retains the previous commit path until migration. The new
  recognizer accepts only prior commit or staging roots under the managed
  Context Guard upstream directory with matching product repository identity;
  unrelated roots remain fail-closed. All schema, protocol, classifier, Hook,
  cache immutability, and private-state contracts are unchanged.
- `0.8.6` corrects the installed lifecycle smoke's direct runtime import. The
  smoke now suppresses bytecode inside its own process, so an invocation
  without an outer environment guard cannot write `__pycache__` or `.pyc` into
  an immutable installed plugin root. Runtime, schema, protocol, classifier,
  Hook, installer, marketplace, cache/archive, and private-state contracts are
  unchanged.
- `0.8.7` is a cache-lifecycle preservation patch. Native Windows 0.8.6
  exposed that Codex replaces the complete plugin cache root during an upgrade;
  product-only archive restoration therefore dropped a retained historical
  `.pyc` that was correctly excluded from product parity. The candidate keeps
  product archives product-only and instead preserves all-file differences in
  a separate SHA-256 transaction, restores them to the same historical live
  version after refresh, and recovers an interrupted transaction before a later
  apply. Read-only diagnosis never recovers or removes the transaction. Schema,
  protocols, classifier, Hook wire, runtime, and private-state contracts remain
  unchanged. Its exact candidate passed native Windows acceptance before the
  release commit was finalized.
- `0.8.8` selects a supported Hook interpreter instead of assuming that the
  first bare `python3` or `python` on `PATH` satisfies the documented Python
  3.10+ requirement. POSIX and Windows launchers probe bounded supported
  candidates by capability, preserve the Hook stdin/stdout contract, and fail
  closed with an actionable stderr message when no supported interpreter is
  available. Schema, protocols, classifier, and private-state contracts remain
  unchanged; the Hook command bytes and installed package identity advance.
- `0.8.9` is a consumed intermediate candidate. Classifier 2.3.1 recognizes
  canonical redaction placeholders and short human-readable quoted examples
  that cannot match Context Guard's URL-safe private token, and removes
  whitespace before token-shape comparison so padded or split token-shaped
  values, private directory/session/turn bindings, control invocations,
  internal markers, and serialized control structures remain fail-closed. It
  was installed into real homes before a release-blocking Hook-lifecycle
  defect was found; its installed cache bytes remain immutable and the version
  number stays consumed.
- `0.8.10` is a consumed intermediate candidate. It folded in the consumed
  0.8.9 classifier work and introduced the Hook command fallback: an observed
  macOS Codex CLI 0.149.0 host prunes historical versioned live caches when a
  fresh task starts and keeps only the current version, so an open task whose
  trusted `$PLUGIN_ROOT` tree disappears loses every later Hook invocation
  until a managed apply restores it from the trusted archive. Both command
  forms prefer the pinned plugin root, fall back to the newest surviving
  non-symlink Context Guard tree under the managed marketplace cache root
  (`CODEX_HOME` when set, otherwise `~/.codex`), and fail closed with an
  actionable reinstall hint. It was installed into a real home and exercised by
  a real task before a review found that its fallback version gate was looser
  than the documented strict-semver contract; its installed cache bytes remain
  immutable and the version number stays consumed.
- `0.8.11` is the 2026-08-27 Hook-lifecycle availability patch that folds in the
  consumed 0.8.9 and 0.8.10 work. Its fallback resolves the newest surviving
  strictly semver-named (exactly three dot-separated numeric components, no
  leading zeros), non-symlink Context Guard tree, with both command forms
  enforcing the same strict gate: POSIX requires exactly three canonical
  numeric components and rejects leading zeros, and Windows matches only
  `X.Y.Z` without leading zeros; a lone `0.0.0` tree is still a valid first
  candidate on both platforms. The fallback executes only trees materialized by
  the host from the sanitized marketplace source; it may run a newer runtime
  than the one a rescued task originally trusted, never mutates consumed
  caches, and leaves the hash-indexed archive as the only authority for
  restoring exact historical trees. Read-only installer diagnosis names host
  startup pruning and its restore action. Schema 7, Proof protocol 1.0.0,
  Stop protocol 1.1.0, Execution protocol 1.0.0, classifier 2.3.1,
  Python 3.10+, and the eight-Hook event set are unchanged; observable Hook
  command bytes and the installed package identity advance.
- `0.8.12` is an unreleased compatible Stop-classifier patch. Classifier 2.3.2
  recognizes a completion phrase inside a bounded quotation followed by a
  Chinese category label such as `类声明` or `这种表述` as meta-discussion rather
  than the assistant's own whole-task completion claim. Standalone quoted
  assertions and explicit first-person confirmations remain gated. Schema 7,
  Proof protocol 1.0.0, Stop protocol 1.1.0, Execution protocol 1.0.0, Python
  3.10+, and the eight-Hook event set are unchanged. The published 0.8.11 cache
  remains immutable.

The project may declare 1.0 only after the public Hook, state, diagnostics,
installer, recovery, compatibility, and deprecation policies are stable;
schema migration and historical-cache recovery have native acceptance on every
supported platform; Stop benchmarks and privacy thresholds have operational
evidence across at least two minor series; this public repository is the sole
implementation upstream and downstream consumers pin immutable public commits;
and rollback behavior lets already-open tasks finish safely.

Proof protocol 1.0.0 guarantees only the deterministic obligations displayed
for an `enforced` item. It does not claim arbitrary pixel understanding,
official-source validity, or semantic completeness for `legacy_fallback` items.
