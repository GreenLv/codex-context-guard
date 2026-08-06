# Local Release Acceptance

This document records local and remote release evidence for standalone Context
Guard `0.4.9`.

## Release contents

- Fresh standalone plugin root with manifest and repo marketplace.
- Complete runtime, eight Hook definitions, state schema 3, Skill,
  successor-pack reference, safe installer, and installed lifecycle smoke.
- English and Simplified Chinese README files, architecture/privacy/
  compatibility documentation, governance files, and Apache-2.0 license.
- Promotional drafts are intentionally maintained outside this repository.
- Nine-job Ubuntu/macOS/Windows and Python 3.10/3.12/3.13 CI matrix.

## Passed locally on macOS for the v0.4.9 release

- Repository contract validation, public-tree privacy audit, manifest checks,
  Ruff, and generated-artifact scan.
- 82 unit/regression tests: 81 pass and one Windows-only PowerShell execution
  test skipped on macOS.
- Runtime parity with the private maintenance source, including the 0.4.7
  user-decision gate and 0.4.8 Windows lock-race hardening.
- Explicit `--codex-home` regression proving marketplace and plugin subprocesses
  cannot fall back to the caller's default Codex home.
- Isolated marketplace installation under Codex CLI 0.146.0, source/cache
  parity, second strict no-op install, and installed lifecycle smoke.
- Lifecycle coverage for schema 3, plan mirror, delegated authority, bounded
  agent results, unknown-evidence exclusion, binary omission, compaction
  recovery, fail-closed state integrity, and private completion gating.
- All eight standalone Hook definitions individually reviewed and trusted under
  `context-guard@codex-context-guard`.
- A fresh isolated task completed a real manual `/compact`, recovered both
  exact acceptance markers in the next turn,
  confirmed no file changes, retained schema 3 with `integrity=ok`, and ended
  with zero continuation attempts.

## Passed locally on Windows after the v0.4.9 tag

- Native Windows 25H2 (build 26200) validation on 2026-08-06 used Python
  3.12.10, Codex CLI 0.146.0, and Ruff 0.16.1.
- The current 83-test suite passed in full under a one-shot elevated Python
  process. With a standard user token, 82 tests passed and only the
  successor-pack symlink rejection test skipped because Windows requires
  Developer Mode or `SeCreateSymbolicLinkPrivilege`; that exact test also
  passed separately under elevation. Developer Mode and the registry were not
  changed. The Windows-only PowerShell Hook execution test and both Windows
  access-denied lock regressions passed.
- Repository contract validation, public-tree privacy audit, and Ruff passed.
- A disposable explicit `--codex-home` registered the repository marketplace,
  installed `context-guard@codex-context-guard` 0.4.9, confirmed source/cache
  parity through a second strict no-op run, and passed the installed lifecycle
  smoke.
- A second disposable Codex home started a fresh interactive task and displayed
  the eight-Hook review prompt. The normal **Trust all and continue** choice
  persisted across resume without using `--dangerously-bypass-hook-trust`, and
  `UserPromptSubmit` completed against the isolated plugin data directory.
- A real manual `/compact` completed the trusted `PreCompact` Hook, then
  `SessionStart` injected a schema-3 recovery packet with valid integrity and
  both test markers. The first backend attempt exposed an incomplete CLI CA
  chain as `UnknownIssuer`; exporting the existing Windows GlobalSign root to
  a disposable PEM bundle and setting the documented `CODEX_CA_CERTIFICATE`
  variable resolved HTTPS and WebSocket trust without changing the system
  certificate store.
- The retried manual `/compact` displayed `Context compacted`. A following
  prompt omitted both marker values and recovered them exactly from the
  `SessionStart` packet. State remained schema 3 with `integrity=ok`, one
  manual compaction, zero continuation attempts, and no project file changes.
- The disposable Codex home, plugin data, Ruff environment, and tool caches
  were removed after validation. The working tree remained unchanged before
  this documentation correction.

The suite grew from 82 to 83 tests after the v0.4.9 tag when the bilingual
README diagram/example parity regression was added. The macOS count above is
the preserved release-time result, not an inferred rerun of the current suite.

## Automated content approval

Core behavior claims map to Hook regressions or installed lifecycle evidence;
installer claims map to safe-install regressions and source/cache parity;
privacy claims map to source inspection, the public-tree scanner, and the
zero-dependency runtime. Platform wording remains bounded by
`COMPATIBILITY.md`.

## Repository and recovery points

- Validated 0.4.9 implementation: the commit carrying this document.
- Pre-0.4.9 public rollback point: `3bf7135d399628e0ba690ea7855e08873a823dfb`.
- Public repository: `https://github.com/GreenLv/codex-context-guard`, default
  branch `main`, public visibility, GitHub noreply commit author.

## Intentionally not claimed

- Linux desktop Hook trust; Linux evidence is CI and isolated lifecycle only.
- Universal plugin-directory submission.
- Publication of the separately maintained CSDN promotional draft.

## Publication gate

A release tag may be created only after the final commit passes all local
gates, remote packaging review, and the full CI matrix. Compatibility wording
must remain bounded by observed evidence.
