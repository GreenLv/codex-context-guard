# Changelog

All notable public releases are documented here.

## Unreleased

No changes yet. Plugin bundle, Hook, manifest, or script changes after the
0.5.1 source line require a new version.

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
