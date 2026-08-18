# Changelog

[简体中文](CHANGELOG.zh-CN.md)

All notable public releases are documented here, newest first. Each version
opens with its highlights in descending priority, followed by grouped changes
and a compact validation note. `0.7.6` is the latest published release.

## 0.7.7 - Unreleased

### Highlights

- Subject discovery no longer turns slash-delimited prose or a path fragment
  inside another URL into a false absolute-path verification obligation.
- Bounded `codex://threads/...` locators remain inspectable subjects, while the
  generic Chinese word for apply no longer implies a UI surface.
- A non-error `view_image` response carrying a valid image data URL is now
  successful visual evidence instead of an unknown result.
- Schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0, and the eight-Hook wire
  remain unchanged; classifier metadata advances to 2.2.1.

### Changes

- The shared runtime and transformed regression contract are synchronized from
  the private sibling under the declared shared-core boundary.
- Public packaging, validation constants, bilingual documentation, and
  installed lifecycle smoke identify 0.7.7 as an unreleased source candidate.

### Validation

- Native Windows source validation passed the public repository and privacy
  audits, sibling parity, 170 tests with one capability-aware skip, the
  eight-Hook self-test, Ruff 0.16.1, compilation, and `git diff --check`.
- An isolated Codex CLI 0.146.0 install passed first install, source/cache
  parity, strict second-run no-op, installed eight-Hook self-test, and lifecycle
  smoke. Public CI/HOL, tagging, release, macOS, and fresh trusted-Hook evidence
  remain separate and are not claimed.

## 0.7.6 - 2026-08-17

### Highlights

- Classifier 2.2.0 closes both blind-spot families found in the 2.1.0 review.
  Plural and quantified completion claims (`All tasks are complete.`,
  `Every requirement is done.`, `任务都完成了。`) and explicit first-person
  reporting (`We report ... complete.`) are now recognized, while questions,
  trailing negations, attributed speech (`他说...`), and hypotheticals
  (`我们假设...`) are no longer treated as completion assertions.
- The Hook entry fails closed on Python older than 3.10 instead of silently
  running an unsupported interpreter.
- Dead code was removed from the shared runtime and installer: two unreferenced
  regexes, an unused clause helper, an unused response formatter, and the
  unused `restore_tree` path. The public 168-test suite and the sibling parity
  gate stay green.
- The 0.7.6 runtime and regression contract are synchronized from the private
  upstream. Schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0, and the
  eight-Hook wire are unchanged.

### Changes

- Version 0.7.4 advances the diagnostic classifier to 2.1.0 and distinguishes
  current-task completion assertions from hypotheticals, attributed quotations,
  and framed examples.
- Version 0.7.5 keeps the protocol surface while bounding negation to the
  latest explicit assistant-future segment and retaining actionable
  review/configuration verbs.
- Version 0.7.6 advances the diagnostic classifier to 2.2.0 and adds the
  fail-closed Python guard.

### Validation

- Scoped native Windows and macOS source plus isolated-install/lifecycle gates
  pass for the public 0.7.6 runtime. The Windows run also verifies sibling
  parity and the installed eight-Hook self-test. A normally trusted public
  fresh-CLI Hook task was not repeated for this patch; CI/HOL and tag checks
  remain separate source-automation gates rather than native-runtime evidence.

## 0.7.3 - 2026-08-14

### Highlights

- State schema 6 with hash-only multimodal assets and deterministic Proof
  protocol 1.0.0: `register-proof` binds evidence to required subjects,
  surfaces, visual readbacks, and normalized scope sets.
- Visual result readback is enforced only for affirmative, authorized mutation
  wording; an unambiguous prompt-explicit complete-scope count outranks the
  attachment count.
- Closes four 0.7.1 regressions found by differential 0.6.3/0.7.1 review:
  control-text false positives, qualitative scope over-enforcement, unbounded
  transcript rescans, and recovery clipping.

### Changes

- `register-proof --manifest` rejects wrong surfaces, unrelated subjects,
  reused input images, and unresolved visual facts.
- Unsupported deterministic boundaries fall back visibly to `legacy_fallback`
  with the compatible 0.6.3 behavior instead of over-claiming.
- Recovery packets preserve bounded asset metadata and outstanding obligations
  without storing image bytes. Stop protocol 1.1.0, classifier 2.0.0, and all
  eight Hook events are unchanged.
- The regression benchmark covers bilingual positive, negative, adversarial,
  multimodal, migration, privacy, and fallback cases, including an anonymized
  48-of-70 subset false-completion replay.

### Validation

- Scoped native macOS and Windows acceptance passed for the frozen 0.7.3
  source, install, archive, strict no-op, and installed lifecycle boundaries.
  Release automation remains source-level evidence and does not replace either
  native run.

## 0.6.3 - 2026-08-12

### Highlights

- Version 0.6.3 keeps state schema 5 and classifier 2.0.0 while advancing the
  Stop protocol to 1.1.0: legacy `continue` is advisory only and terminal
  control is one-way safe.
- Private-control intent detection is scoped to recognized shell tools and
  quoted operators, so documentation patches and plain `rg`/`grep` searches no
  longer look like control writes.
- Cache upgrades repair indexed live versions from trusted archives before
  adopting anything unindexed, and remove legacy archive `.git` metadata only
  after the indexed product manifest matches.

### Changes

- A schema-5 state with an in-flight protocol-1.0.0 control invalidates only
  that ephemeral attempt; prompts, items, evidence, and decisions are intact.
- The 0.6.2 cache was consumed by a real installation before these manager
  fixes and remains untagged and unreleased.

### Validation

- Regression replay covers the terminal mismatch class, explicit persistence,
  quoted-search and non-shell boundaries, and 10,000 staged-control
  transitions. Native macOS and Windows acceptance passed; the published 0.6.3
  release is built from the validated `main` commit with matching annotated
  tag and GitHub Release. CI/HOL remain source-level gates, not native
  acceptance.

## 0.6.1 - 2026-08-11

### Highlights

- Schema 5 turn control: one private `completion_attempt.staged_control` slot
  for a verified checkpoint or one of `continue` / `user_wait` / `external_wait`
  / `deferred`; `complete` is derived only from a checkpoint.
- Stop protocol 1.0.0 with classifier 2.0.0 diagnostics records decision
  source, declared disposition, observed outcome, bounded enums, and hashes
  without retaining raw reply text.
- Adds the final standalone `Script completed` receipt so a raw-stdout Code
  Mode tool response can prove the same success as a structured one.

### Changes

- The 0.6.x line is a protocol-first turn-control minor, first implemented in
  the unreleased 0.6.0 candidate. The exact eight Hook events are unchanged.
- `PostToolUse` remains the only authoritative staging writer after verifying
  command, data directory, session, turn, token, marker, and successful
  outcome.
- Stop applies a fixed priority: integrity and private-metadata checks, a
  verified checkpoint, an uncheckpointed whole-completion claim, staged
  `continue`, explicit persistence, typed wait/deferred, then safe yield.
- Schema 1–4 migration preserves the ledger but invalidates in-flight tokens
  and staged controls; public release validation audits commit identities with
  redacted failures.
- The bilingual README reports an anonymized token-overhead range.
  Requirement-to-evidence semantic relevance is not implemented in 0.6.x; it
  remains benchmark-first research.

### Validation status

- Version 0.6.0 was never tagged or released; its cache bytes are immutable
  and its number consumed. Version 0.6.1 passed native macOS and Windows
  acceptance and gates publication on the exact release commit passing PR/main
  CI and HOL plus tag CI. No 0.6.0 tag may be created.

## 0.5.1 - 2026-08-10

### Highlights

- Stop classifier 1.0.1 separates explicit user handoffs from independent
  assistant futures in the same reply.
- Persisted `open_items` is recomputed on load and save, normalizing stale
  schema-3/4 derived state.

### Fixed

- Same-version first archive adoption is allowed only under the install lock
  after exact source/cache parity and archive integrity are proved; drift,
  corruption, and unindexed archives still fail closed.

### Validation

- Adds bilingual handoff/authority matrices, stale-state migration, and
  first-adoption archive regressions. Native macOS (111 private / 108 public
  tests) and native Windows 0.5.1 acceptance pass independently.

## 0.5.0 - 2026-08-09

### Highlights

- State schema 4 with a bounded 32-entry hash-only `decision_log`; schemas 1,
  2, and 3 migrate with an empty diagnostic history.
- Stop classifier 1.0.0 with stable allow/gate/consume/fail-closed outcomes,
  reason codes, action category, owner, and current-turn authorization.
- Versioned archive lifecycle under `CODEX_HOME/plugins/cache-archive/` with an
  atomic SHA-256 index, explicit trusted repair, and no automatic pruning.

### Changes

- `context-guard diagnose` plus classifier/latest-decision fields in `status`;
  a documented version policy and sibling-product shared-core parity gate.
- Deferred remote work stays safe only when denied or out of scope; broad
  authority and double-negated commands remain gated, and external-review
  sentences cannot hide assistant-owned follow-up work.
- Live historical caches are repaired only from intact trusted archives.

### Validation

- Seven observed/adversarial phase-boundary cases plus bilingual metamorphic
  scope, schema migration/privacy/rebuild, and archive-lifecycle tests. Native
  Windows 0.5.0 acceptance was recorded later; no tag or GitHub Release was
  created by this source update.

## 0.4.16 - 2026-08-09

Versions 0.4.14 and 0.4.15 were unpublished local candidates. Their numbers
remain consumed because an installed versioned Hook cache is never overwritten
in place.

### Fixed

- Deferred-phase status reports are interpreted together with the current
  prompt instead of completion words alone, and bounded review/audit/test/
  verification/local-commit/reporting turns may end after explicitly leaving a
  later phase unresolved.
- The completion gate is preserved when the current prompt asks to continue,
  finish, push, publish, deploy, promote, create a remote, or run CI, reading
  the full immutable prompt record rather than the bounded recovery summary.
- Explicit boundaries such as "do not push or run CI" count as denied
  authority; affirmative execution requests stay gated, and the gate fails
  closed when the prompt record, path, or digests no longer match.

### Validation

- Nine-job Ubuntu/macOS/Windows CI matrix on Python 3.10, 3.12, and 3.13,
  repository validation, public-tree audit, 91 tests, Ruff, bytecode
  compilation, and the mandatory HOL Plugin Scanner all pass.

## 0.4.13 - 2026-08-08

### Fixed

- Status-only replies about submitted external reviews, platform selection,
  policy holds, and intentionally unchanged repositories are valid
  non-completion boundaries even when a local status sentence uses a
  completion word.
- The same whole-message non-completion classifier applies to completion
  detection and Stop handling, including staged-checkpoint cleanup.

## 0.4.12 - 2026-08-08

Version 0.4.11 was an unpublished local candidate; its number remains consumed
so an installed versioned Hook cache is never overwritten in place.

### Fixed

- Explicit user-action handoffs such as login, publisher configuration,
  deployment approval, and reply-after-action are valid non-completion
  boundaries even when the reply reports completed local milestones.
- The completion gate is retained when a reply lists actionable remaining work
  without handing control to the user, and handoff phrases require an explicit
  user subject or reply-to-agent instruction.

## 0.4.10 - 2026-08-07

### Distribution

- Text-free shield-and-checkpoint SVG icon exposed through
  `interface.composerIcon`; pinned GitHub Actions references and validation
  tool lock; mandatory HOL scanner gate with SARIF upload, score 80 minimum,
  and high-severity failure threshold.

### Documentation

- Rendered, visually checked bilingual Mermaid flowcharts and lifecycle
  sequence; bilingual everyday refactoring case covering constraint,
  correction, `/compact` recovery, and evidence-gated completion.

### Validation

- Native Windows 25H2 (build 26200, Python 3.12.10) passed 83 tests; a standard
  user token passed 82 plus the separately elevated symlink test. A disposable
  `--codex-home` install passed strict no-op and lifecycle smoke, and a fresh
  Windows task completed normal Hook trust plus real manual `/compact` recovery
  with no project file changes.

## 0.4.9 - 2026-08-06

First public release, based on the validated Context Guard 0.4.8 runtime
lineage.

### Fixed

- The installer routes every Codex subprocess through the explicit
  `--codex-home` value instead of silently using the caller's default home.

### Validation status

- macOS: all eight Hooks were individually reviewed and trusted; a fresh CLI
  task completed real manual `/compact`, recovered both acceptance markers,
  and made no file changes.
- Windows: CI validated Python 3.10, 3.12, and 3.13; native fresh-runtime
  verification remained pending at release.
- Linux: CI and isolated installed-lifecycle evidence only; no desktop Hook
  trust claim.

## 0.4.8 - superseded release candidate

Initial open-source candidate based on the validated Context Guard 0.4.8
lineage. This candidate was not tagged; 0.4.9 supersedes it with the installer
isolation fix and completed standalone trusted-runtime gate.

### Included

- Immutable hash-verified prompt journaling and requirement/acceptance ledger;
  explicit supersession tracking and fail-closed ambiguous revisions.
- Bounded compaction recovery, native plan mirror, provenance-aware delegated
  contracts, structured evidence capture, and private completion gating.
- Safe local installer that rejects same-version drift and preserves older
  versioned Hook caches.
- User-decision-gate precedence so approval-awaiting replies do not trigger
  repeated Stop Hook continuations.
- Windows lock-race hardening with bounded retry for access-denied results that
  outlive a previous holder's lock.

### Validation status

- macOS source lineage: 80 local tests plus one Windows-only skip, plugin
  validation, privacy audit, parity, idempotent install, and isolated lifecycle
  smoke; the 9-job CI matrix passed twice. Windows native runtime verification
  remained pending; Linux was CI-only.
