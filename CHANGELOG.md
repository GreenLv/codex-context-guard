# Changelog

All notable public releases are documented here.

## 0.4.8 - unreleased candidate

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

The candidate is not a published GitHub release until the remaining standalone
Hook trust/runtime gate passes and the release tag is created.
