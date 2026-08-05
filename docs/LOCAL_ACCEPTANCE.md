# Local Release-Candidate Acceptance

This document records the local, pre-publication evidence for the standalone
`0.4.6` candidate. It is not evidence that GitHub CI or a public release exists.

## Candidate contents

- Fresh standalone plugin root with manifest and repo marketplace.
- Complete Context Guard 0.4.6 runtime, eight Hook definitions, state schema 3,
  Skill, successor-pack reference, installer, and installed lifecycle smoke.
- English and Simplified Chinese README files, architecture/privacy/
  compatibility documentation, governance files, and CSDN draft.
- Apache-2.0 license and a nine-job cross-platform CI matrix definition.

## Passed locally on macOS

- Standalone repository contract validation.
- Public-tree privacy and generated-artifact audit.
- Plugin manifest validation.
- 78 unit/regression tests, with one Windows-only PowerShell execution test
  skipped on macOS.
- Ruff validation.
- Isolated marketplace registration and plugin installation using Codex CLI
  0.146.0.
- Source/cache parity and a second same-version strict no-op install.
- Isolated installed lifecycle smoke covering schema 3, plan mirror, delegated
  authority, bounded agent result, unknown-evidence exclusion, binary omission,
  compaction recovery, and private completion gating.

## Intentionally pending

- Human review and acceptance of the local repository.
- A fresh interactive Codex task that reviews/trusts the standalone Hook
  identity and performs a real manual `/compact` without trust bypass.
- GitHub repository creation, push, public CI, release tag, and release notes.
- Native Windows 0.4.6 fresh-runtime validation. Until it exists, Windows may
  be described only by automated CI evidence after that CI passes.
- Linux claims beyond automated CI and isolated lifecycle validation.
- Remote Git marketplace packaging behavior. Codex CLI 0.146.0 copied the
  entire fresh local repository root, including local `.git` and ignored Finder
  metadata, into the isolated plugin cache because this repository intentionally
  uses `source.path: "./"`. The staged public tree remains clean and contains no
  private history, but the remote marketplace snapshot must be re-audited before
  release and this behavior must not be generalized to older/private histories.
- Universal plugin-directory submission and CSDN publication.

## Publication gate

Do not publish or tag this candidate until the human acceptance step is
explicitly granted. After publication, update compatibility and blog wording
only from observed CI and runtime evidence.
