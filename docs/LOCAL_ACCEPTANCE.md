# Local Release-Candidate Acceptance

This document records the local, pre-publication evidence for the standalone
`0.4.8` candidate. The repository is public, but this document is not evidence
that the final 0.4.8 CI or GitHub Release exists.

## Candidate contents

- Fresh standalone plugin root with manifest and repo marketplace.
- Complete Context Guard 0.4.8 runtime, eight Hook definitions, state schema 3,
  Skill, successor-pack reference, installer, and installed lifecycle smoke.
- English and Simplified Chinese README files, architecture/privacy/
  compatibility documentation, and governance files. Promotional drafts are
  intentionally maintained outside this public repository.
- Apache-2.0 license and a nine-job cross-platform CI matrix definition.

## Passed locally on macOS

- Standalone repository contract validation.
- Public-tree privacy and generated-artifact audit.
- Plugin manifest validation.
- 81 unit/regression tests: 80 pass, with one Windows-only PowerShell execution
  test skipped on macOS.
- The 0.4.8 runtime matches the private maintenance source exactly, retains the
  0.4.7 user-decision gate, and adds regressions for both the Windows
  access-denied/holder-exit race and unrelated POSIX permission failures.
- Ruff validation.
- Isolated marketplace registration and plugin installation using Codex CLI
  0.146.0.
- Source/cache parity and a second same-version strict no-op install.
- Isolated installed lifecycle smoke covering schema 3, plan mirror, delegated
  authority, bounded agent result, unknown-evidence exclusion, binary omission,
  compaction recovery, and private completion gating.

## Automated content approval

The local candidate is approved by the repository's automated gates. Core
behavior claims map to Hook regressions or the installed lifecycle smoke;
installer claims map to safe-install regressions and isolated source/cache
parity; privacy claims map to source inspection, the public-tree scanner, and
the zero-dependency Hook runtime. Platform wording remains limited to the
evidence table in `COMPATIBILITY.md`.

This approval covers the local source candidate. The public repository and
`main` branch now exist, but this evidence does not make corrected remote CI
green, establish native Windows parity, or create a release tag.

## Candidate and recovery point

- Validated 0.4.7 implementation candidate: `547e81d`.
- Pre-0.4.7 local baseline and rollback point: `7dc13b5`.
- The standalone repository has no remote configured at this gate.

## Intentionally pending

- Final tag and Release creation after the corrected public CI is green.
- A fresh interactive Codex task that reviews/trusts the standalone Hook
  identity and performs a real manual `/compact` without trust bypass.
- Corrected public CI, release tag, and release notes.
- Native Windows 0.4.8 fresh-runtime validation. Until it exists, Windows may
  be described only by automated CI evidence after that CI passes.
- Linux claims beyond automated CI and isolated lifecycle validation.
- Remote Git marketplace packaging behavior. Codex CLI 0.146.0 copied the
  entire fresh local repository root, including local `.git` and ignored Finder
  metadata, into the isolated plugin cache because this repository intentionally
  uses `source.path: "./"`. The staged public tree remains clean and contains no
  private history, but the remote marketplace snapshot must be re-audited before
  release and this behavior must not be generalized to older/private histories.
- Universal plugin-directory submission and external promotional publication.

## Publication gate

External repository publication is authorized and `main` is public. Do not tag
or create a GitHub Release until corrected public CI, remote packaging review,
and the remaining release checks pass. Update compatibility wording only from
observed CI and runtime evidence.
