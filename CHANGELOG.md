# Changelog

All notable public releases are documented here.

## 0.4.6 - unreleased candidate

Initial open-source candidate based on the validated Context Guard 0.4.6
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

### Validation status

- macOS source lineage: Hook regressions, safe-install regressions, installed
  lifecycle, and fresh no-bypass runtime smoke were previously verified. The
  standalone public identity now passes 78 local tests (one Windows-only skip),
  plugin validation, privacy audit, source/cache parity, idempotent install, and
  isolated installed lifecycle smoke; manual trusted `/compact` remains pending.
- Windows: automated CI is required for this repository. Native 0.4.6 fresh
  runtime verification remains pending and must not be inferred from CI.
- Linux: automated CI and isolated lifecycle validation only; no desktop Hook
  trust claim.

The candidate is not a published GitHub release until human acceptance and a
green public CI run.
