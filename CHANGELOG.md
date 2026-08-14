# Changelog

All notable public releases are documented here.

## Unreleased

## 0.7.3 - 2026-08-14

### Added

- State schema 6 adds hash-only multimodal assets, immutable verification
  contracts, and Proof protocol 1.0.0 bindings for subjects, verification
  surfaces, visual facts/readbacks, and normalized scope coverage.
- `register-proof --manifest` validates an item-scoped proof against successful,
  fresh, capability-compatible evidence. Proper subsets, wrong surfaces,
  unrelated subjects, reused input images, and unresolved visual facts fail.

### Changed

- Version 0.7.3 requires an affirmative, authorized mutation clause before
  adding a visual result-readback obligation; negated, denied, and out-of-scope
  mutation wording remains inspection-only. An unambiguous prompt-explicit
  complete-scope count now takes precedence over attachment count, preventing
  five screenshots from narrowing an explicitly requested 70-item audit.
- Version 0.7.2 closes four regressions found by differential 0.6.3/0.7.1
  review: ordinary command text containing `register-proof` is evidence rather
  than a control attempt; qualitative complete-scope wording without a
  prompt-derived expected set uses `legacy_fallback`; transcript reconciliation
  is bounded to once per prompt during tool use with forced lifecycle retries;
  and recovery clipping reserves the completion rule.
- Version 0.7.1 reconciles late transcript attachment metadata before the first
  `PostToolUse` evidence. The native fresh-task gate consumed 0.7.0 before
  exposing this prompt-association defect, so 0.7.0 remains immutable and
  unreleased.
- Completion checkpoints enforce every deterministic proof obligation. When an
  attachment or semantic boundary cannot be established deterministically, the
  item is marked `legacy_fallback` and retains the compatible 0.6.3 behavior.
- Recovery packets preserve bounded asset metadata and outstanding obligations
  across compaction without storing image bytes. Stop protocol 1.1.0,
  classifier 2.0.0, and all eight Hook events remain unchanged.

### Validation

- The regression benchmark covers Chinese and English positive, negative,
  adversarial, multimodal, cross-item, migration, privacy, and fallback cases,
  including an anonymized 48-of-70 subset false-completion replay.
- A compatibility matrix replays the 0.6.3 command behavior, locks
  prompt-constructible scope and qualitative abstention, asserts the transcript
  scan-count invariant, and preserves the pre-0.7 recovery-capacity threshold.
- Scoped native macOS and Windows acceptance passed for the frozen 0.7.3
  source, installation, archive, strict no-op, and installed lifecycle
  boundaries. Release automation remains source-level evidence and does not
  replace either native run.

## 0.6.3 - 2026-08-12

### Changed

- Version 0.6.3 keeps state schema 5 and classifier 2.0.0 while advancing the
  Stop protocol to 1.1.0. The legacy `continue` disposition remains accepted
  for wire compatibility but is advisory only; it can no longer force another
  turn after an assistant has already produced a terminal reply.
- Terminal control is now one-way safe: absent a verified whole-task completion
  claim or a hash-verified explicit persistence instruction, every disposition
  mismatch degrades to a safe yield with pending work preserved.
- Private-control intent detection is limited to recognized shell-execution
  tools and detects operators only outside quoted literals. Documentation
  patches and pure `rg`/`grep` searches can mention control subcommands and
  regex alternation without being misclassified as an attempted control write.
- Loading a schema-5 state with an in-flight protocol-1.0.0 control invalidates
  only that ephemeral attempt; prompts, requirements, acceptance items,
  evidence, and historical decisions remain intact.
- Cache upgrades now repair every indexed live version from its trusted archive
  before adopting any unindexed live version. Legacy archive `.git` metadata is
  removed only after the indexed product manifest matches and remains unchanged;
  read-only audit still fails closed. Version 0.6.2 was consumed by a real
  installation before these manager fixes and remains untagged and unreleased.

### Validation

- The regression suite replays the terminal mismatch class, checks explicit
  persistence separately, covers quoted-search and non-shell-tool boundaries,
  and deterministically exercises 10,000 staged-control transitions and policy
  states. Scoped native macOS private/public installed and fresh-runtime
  acceptance passes, including normally trusted `user_wait`, completion
  checkpoint, and manual schema-5 `/compact` recovery. Public PR #8 at package
  head `d3df09b0ba92797ca03a26a856b6669c3f52b54c` passes the nine-job CI matrix,
  HOL Scanner, and plugin-scanner. Native Windows independently passes the
  frozen private/public source, installed, archive, parity, boundary, lifecycle,
  normal-trust real-wire, negative-control, doctor, and manual-compaction gates.
  The 0.6.3 release is published from the validated `main` commit. Its
  annotated tag and GitHub Release preserve that exact source state. Release
  automation is source-level evidence and does not replace either native run.

## 0.6.1 - 2026-08-11

### Added

- The 0.6.x line is a protocol-first turn-control minor. State schema
  5 adds one turn-bound `completion_attempt.staged_control` slot for either a
  verified completion checkpoint or one non-completion disposition:
  `continue`, `user_wait`, `external_wait`, or `deferred`. This contract was
  first implemented in the unreleased 0.6.0 candidate and is carried forward
  unchanged by the 0.6.1 release.
- The private `stage-disposition` command preflights a typed disposition. The
  existing `PostToolUse` Hook remains the only authoritative writer after it
  verifies the exact command, data directory, session, turn, private token,
  marker, and successful tool outcome. Structured status is used when present;
  the 0.6.1 raw-stdout path uses the final private success receipt.
- Stop protocol 1.0.0 and classifier 2.0.0 diagnostics record the decision
  source, declared disposition, observed outcome, bounded reason/action enums,
  and prompt/reply hashes without retaining raw reply text.
- Public release validation now audits every PR or push commit's author and
  committer for a GitHub noreply identity. Rejected values stay redacted so a
  misconfigured Windows clone cannot leak a personal email into CI logs while
  failing the release gate.

### Fixed

- The 0.6.1 release adds a final standalone `Script completed` receipt after
  each successful private `stage-checkpoint` or `stage-disposition` precheck.
  This lets a real Code Mode `PostToolUse` raw-stdout response establish the
  same successful outcome as a structured success response.
- A bare private marker remains insufficient. Structured failure, an explicit
  nonzero exit status, or a hard failure marker takes priority over the success
  receipt, and private control commands remain excluded from requirement-
  closing evidence.

### Changed

- Stop now applies a fixed control priority: integrity and private-metadata
  checks; a verified checkpoint; an uncheckpointed whole-task completion
  claim; staged `continue`; explicit user persistence; typed wait/deferred;
  then safe default yield. `complete` is derived only from a verified
  checkpoint and is not a disposition.
- `continue` requests bounded continuation. `user_wait`, `external_wait`, and
  `deferred` yield without changing pending requirements. With no staged
  control, an incomplete response also yields safely unless an explicit
  whole-task completion claim or user persistence requires continuation; a
  genuine user/external wait may still yield under persistence, and `deferred`
  may do so only when the hash-verified prompt denies or excludes the specific
  action identified as deferred.
- Natural-language action classification is diagnostic and anomaly-oriented;
  it no longer drives ordinary continuation from inferred action ownership.
- Schema 1-4 migration preserves the durable ledger but invalidates any
  in-flight completion token or staged control so a fresh turn must authorize
  the schema-5 protocol.
- The exact eight Hook events and their Codex payload shapes are unchanged.
  Requirement-to-evidence semantic relevance is not implemented in 0.6.x; it
  remains benchmark-first research for a possible 0.7.0 capability.
- The bilingual README now reports an anonymized, observational token-overhead
  range so adopters can estimate the order of magnitude without exposing task,
  account, path, or absolute-usage metadata.

### Validation status

- Version 0.6.0 was never tagged or released. A normally trusted fresh Codex
  Code Mode run delivered the private marker as raw stdout without a structured
  exit status; the generic outcome remained unknown and two valid disposition
  staging attempts failed closed. Because 0.6.0 had already been installed, its
  cache bytes are immutable and its version number is consumed.
- Version 0.6.1 passed native macOS and Windows acceptance. Source/live/archive
  parity, installed lifecycle, and Context Guard doctor subchecks pass.
  Normally trusted private and public identities,
  without a bypass, also pass `user_wait`, completion checkpoint, and manual
  schema-5 `/compact` recovery. Publication is gated on the exact release
  commit passing PR/main CI and HOL plus tag CI. These checks are source-level
  automation, not installed-runtime or native-platform acceptance. No 0.6.0
  tag may be created.

## 0.5.1 - 2026-08-10

### Fixed

- Stop classifier 1.0.1 separates explicit user handoffs from independent
  assistant futures in the same reply. Work conditioned on a user's login,
  unlock, confirmation, or reply may end safely, while work promised in
  parallel or without that dependency remains gated by current-turn authority.
- Persisted `open_items` is recomputed from requirement and acceptance status
  during load and save, normalizing trusted schema-3 and schema-4 states whose
  older derived value was stale.
- A same-version current plugin may establish its first trusted archive without
  reinstalling or overwriting the cache, but only under the install lock after
  exact source/cache parity and archive integrity are proved. Other untrusted
  live versions, unindexed archive directories, corruption, and drift continue
  to fail closed.

### Validation scope

- Adds sanitized bilingual user-handoff/assistant-future matrices, bounded and
  broad authority metamorphic cases, stale derived-state migration tests, and
  first-adoption archive regressions.
- macOS local acceptance covers 111 private tests with one platform skip, 108
  public tests with one platform skip, repository/privacy/boundary/parity/Ruff/
  compilation gates, private and isolated-public installed lifecycles, and a
  fresh no-bypass classifier 1.0.1 handoff task.
- Native Windows 0.5.1 acceptance independently covers the source and installed
  suites, manager/export/share-boundary gates, repository/privacy/Ruff checks,
  isolated first-adoption, 19-version archive audit, installed lifecycle,
  eight-Hook self-test, doctor, and a fresh no-bypass classifier 1.0.1 handoff.

## 0.5.0 - 2026-08-09

### Added

- State schema 4 with a bounded 32-entry, hash-only `decision_log`; schema 1,
  2, and 3 migrate with an empty diagnostic history.
- Stop classifier 1.0.0 with stable allow/gate/consume/fail-closed outcomes,
  reason codes, action category, owner, and current-turn authorization.
- `context-guard diagnose` plus classifier/latest-decision fields in `status`.
- Persistent version archives under `CODEX_HOME/plugins/cache-archive/` with
  an atomic SHA-256 index, explicit trusted repair, and no automatic pruning.
- A documented version policy and sibling-product shared-core parity gate.

### Fixed

- Treat deferred remote work as safe only when it is denied or outside the
  current bounded scope; explicit broad authority and double-negated commands
  remain gated.
- Prevent an external-review sentence from hiding assistant-owned repository,
  publication, CI, or review-followup work in another clause.
- Repair live historical caches after install-time or delayed deletion only
  when an intact trusted archive exists; archive corruption fails closed.

### Validation scope

- Adds the seven observed/adversarial phase-boundary cases, bilingual
  metamorphic scope tests, schema migration/privacy/rebuild tests, and cache
  archive creation/deletion/corruption/no-op/concurrency tests.
- Native Windows 0.5.0 acceptance was recorded later and is not inferred from CI.
- No `v0.5.0` tag or GitHub Release is created by this source update.

## 0.4.16 - 2026-08-09

Versions 0.4.14 and 0.4.15 were unpublished local candidates. Their numbers
remain consumed because full-prompt integrity and negated-action handling were
hardened after those caches had already been installed; an installed versioned
Hook cache is never overwritten in place.

### Fixed

- Interpret deferred-phase status reports together with the current user prompt
  instead of relying only on completion words in the assistant reply.
- Let bounded review, audit, test, verification, local-commit, and reporting
  turns end after they explicitly leave a later phase unresolved.
- Preserve the completion gate when the current prompt explicitly asks to
  continue, finish the whole or remaining task, push, publish, deploy, promote,
  create a remote, or run CI.
- Read the full immutable current-prompt record for this decision instead of
  the bounded recovery summary, so broad authorization after a long prefix is
  not accidentally hidden.
- Treat explicit boundaries such as "do not push or run CI" as denied authority,
  while keeping "do not skip pushing" and affirmative execution requests gated.
- Fail closed if the full prompt record, its path, or either stored digest no
  longer matches the private ledger.
- Add bilingual positive and adversarial regressions based on the observed
  local-commit / later-push boundary, including a prompt longer than the
  recovery-summary limit.

### Validation

- Pass the nine-job Ubuntu, macOS, and Windows matrix on Python 3.10, 3.12, and
  3.13, including repository validation, public-tree audit, 91 tests, Ruff, and
  bytecode compilation.
- Pass the mandatory HOL Plugin Scanner workflow.

## 0.4.13 - 2026-08-08

### Fixed

- Recognize status-only replies about submitted external reviews, platform
  selection, explicit policy holds, and intentionally unchanged repositories
  as valid non-completion boundaries, even when a local status sentence uses a
  completion word.
- Apply the same whole-message non-completion classifier in both completion
  detection and Stop handling, including staged-checkpoint cleanup.
- Add bilingual positive and adversarial regressions from the observed task:
  external waits and explicit pauses end once, while assistant-owned submit,
  publish, promote, and repository-update follow-ups still trigger the gate.

## 0.4.12 - 2026-08-08

Version 0.4.11 was an unpublished local candidate. Its number remains consumed
so an already installed versioned Hook cache is never overwritten in place.

### Fixed

- Recognize explicit user-action handoffs such as account login, publisher
  configuration, deployment approval, and reply-after-action instructions as
  valid non-completion boundaries, even when the same reply reports completed
  local milestones.
- Retain the completion gate when a reply merely lists actionable remaining
  work without actually handing control to the user.
- Require an explicit user subject or a reply-to-agent instruction for the new
  handoff phrases, so assistant-owned follow-up work still triggers the gate.

## 0.4.10 - 2026-08-07

### Distribution readiness

- Added a text-free shield-and-checkpoint SVG icon and exposed it through
  `interface.composerIcon`.
- Added immutable-SHA GitHub Actions references, a pinned validation-tool lock,
  and the mandatory HOL scanner gate with SARIF upload, score 80 minimum, and
  high-severity failure threshold.
- Added CI, scanner, release, and license badges plus a short sanitized
  compact/recovery demonstration.

### Documentation

- Replaced the README ASCII architecture sketch with rendered and visually
  checked Mermaid flowcharts in English and Simplified Chinese.
- Added a bilingual everyday refactoring case that follows initial constraints,
  a later correction, `/compact` recovery, and evidence-gated completion.
- Added an end-to-end Mermaid lifecycle sequence to the architecture document
  and a regression that keeps the bilingual diagrams and example aligned.
- Reconciled the post-tag 83-test suite and native Windows verification status
  across the acceptance, compatibility, and bilingual README documentation.

### Validation

- Native Windows 25H2 (build 26200) with Python 3.12.10 passed all 83 current
  tests under a one-shot elevated test process. A standard user token passed 82
  and skipped only the symlink rejection test; that test also passed separately
  under elevation. Developer Mode and the registry were not changed. The
  Windows-only PowerShell Hook execution and both Windows lock regressions
  passed.
- Repository validation, public-tree audit, and Ruff 0.16.1 passed. A
  disposable `--codex-home` installed plugin 0.4.9 under Codex CLI 0.146.0,
  passed a second strict no-op check and the installed lifecycle smoke, and was
  then removed.
- A fresh Windows task completed the normal persistent Hook trust flow without
  the trust-bypass flag. `UserPromptSubmit` ran, and a real manual `/compact`
  completed `PreCompact`, backend compaction, and recovery-packet injection
  through `SessionStart`. After the Windows GlobalSign root was supplied to
  the isolated CLI through `CODEX_CA_CERTIFICATE`, post-compact blind recall
  recovered both exact markers with no project file changes.

## 0.4.9 - 2026-08-06

First public release, based on the validated Context Guard 0.4.8 runtime
lineage.

### Fixed

- The installer now routes every Codex subprocess through the explicit
  `--codex-home` value. Previously, validation could inspect an isolated home
  while marketplace/plugin commands silently used the caller's default home.
- Added a regression that observes the subprocess environment and prevents
  recurrence of that isolation failure.

### Validation status

- macOS: all eight standalone Hooks were individually reviewed and trusted;
  a fresh Codex CLI 0.146.0 task then completed a real manual `/compact`,
  recovered both exact acceptance markers, made no file changes, retained
  schema 3 with valid integrity, and required no Stop-Hook continuation.
- Windows: at release, the final 0.4.9 CI matrix validated Python 3.10, 3.12,
  and 3.13; native fresh-runtime verification remained pending.
- Linux: CI and isolated installed-lifecycle evidence only; desktop Hook trust
  is not claimed.

## 0.4.8 - superseded release candidate

Initial open-source candidate based on the validated Context Guard 0.4.8
lineage.

### Included

- Immutable, hash-verified prompt journaling and requirement/acceptance ledger.
- Explicit supersession tracking and fail-closed ambiguous revision handling.
- Bounded compaction recovery and a read-only mirror of native plan state.
- Provenance-aware delegated-agent contracts and bounded result summaries.
- Structured evidence capture, binary omission, and private completion gating.
- State integrity verification, reconstruction from immutable prompt records,
  redacted handoff export, and explicit bounded successor packs.
- Safe local installer that rejects same-version drift and preserves older
  versioned Hook caches during upgrades.
- User-decision-gate precedence so replies that explicitly await approval,
  authorization, confirmation, or input do not trigger repeated Stop Hook
  continuations merely because they also report a completed local milestone.
- Windows lock-race hardening so an access-denied result that outlives the
  previous holder's lock file is retried within the existing timeout, while
  unrelated POSIX permission failures still fail immediately.

### Validation status

- macOS source lineage: Hook regressions, safe-install regressions, installed
  lifecycle, and fresh no-bypass runtime smoke were previously verified. The
  standalone public identity now passes 80 local tests plus one Windows-only
  skip (81 total),
  plugin validation, privacy audit, source/cache parity, idempotent install, and
  isolated installed lifecycle smoke. The 9-job public CI matrix passed twice
  on the same 0.4.8 commit; manual standalone trusted `/compact` remains pending.
- Windows: public CI passes on Python 3.10, 3.12, and 3.13, including two runs
  of the lock regression. Native 0.4.8 runtime verification remains pending and
  must not be inferred from CI.
- Linux: public CI and isolated lifecycle validation only; no desktop Hook
  trust claim.

This candidate was not tagged; 0.4.9 supersedes it with the installer isolation
fix and completed standalone trusted-runtime gate.
