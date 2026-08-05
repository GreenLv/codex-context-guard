# Local Release-Candidate Acceptance

This document records the local and remote pre-release evidence for the standalone
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
- Public CI run `31042727226` passed the full 9-job Ubuntu/macOS/Windows and
  Python 3.10/3.12/3.13 matrix twice on commit `aea493d`, including two
  successful Windows Python 3.13 lock-regression executions.
- A fresh clone from the public GitHub URL passed repository validation,
  privacy audit, first install, same-version strict no-op, source/cache parity,
  and installed lifecycle smoke.
- The remote-clone plugin cache contains the repository `.git` directory due
  to the required root-level marketplace layout. It contains only six fresh
  public commits, one GitHub noreply author, and no Finder/Python cache files or
  private history.

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

- Validated 0.4.8 implementation candidate: `aea493d`.
- Pre-0.4.8 public rollback point: `bfc2884`.
- Public repository: `https://github.com/GreenLv/codex-context-guard`, default
  branch `main`, public visibility, GitHub noreply commit author.

## Intentionally pending

- Final tag and Release creation after the standalone trusted runtime gate.
- A fresh interactive Codex task that reviews/trusts the standalone Hook
  identity and performs a real manual `/compact` without trust bypass.
- Corrected public CI, release tag, and release notes.
- Native Windows 0.4.8 fresh-runtime validation. Until it exists, Windows may
  be described only by automated CI evidence after that CI passes.
- Linux claims beyond automated CI and isolated lifecycle validation.
- Universal plugin-directory submission and external promotional publication.

## Publication gate

External repository publication is authorized and `main` is public. Do not tag
or create a GitHub Release until corrected public CI, remote packaging review,
and the remaining release checks pass. Update compatibility wording only from
observed CI and runtime evidence.
