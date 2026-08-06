# Changelog

All notable public releases are documented here.

## Unreleased

### Documentation

- Replaced the README ASCII architecture sketch with rendered and visually
  checked Mermaid flowcharts in English and Simplified Chinese.
- Added a bilingual, sanitized real `/compact` acceptance case that shows exact
  requirement recovery and evidence-gated completion without exposing private
  task state.
- Added an end-to-end Mermaid lifecycle sequence to the architecture document
  and a regression that keeps the bilingual diagrams and example aligned.

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
- Windows: the final 0.4.9 CI matrix validates Python 3.10, 3.12, and 3.13;
  native fresh-runtime verification remains pending.
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
