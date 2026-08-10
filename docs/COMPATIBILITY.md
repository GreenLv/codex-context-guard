# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Context Guard plugin: `0.5.1`
- Private state schema: `4`
- Stop classifier: `1.0.1`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## Release status

| Platform | Automated tests | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | private 87 Hook tests (86 pass, 1 Windows-only skip), private combined 111 tests, and public standalone 108 tests (107 pass, 1 skip), repository validation, public-tree audit, complete share-boundary/parity, Ruff 0.16.1, and source compilation pass | private persistent 0.5.1 cache/archive and isolated public 0.5.1 install/no-op/archive/lifecycle verified with Codex CLI 0.146.0 | fresh private-identity task loaded classifier 1.0.1 without trust bypass and ended a user-dependent handoff with zero continuations and no project writes | native private 0.5.1 runtime plus isolated public lifecycle verified; fresh public-identity Hook trust was not repeated |
| Windows | native 0.5.0 source and installed-cache Hook suites each ran 84 tests with one capability-aware symbolic-link skip; manager, export, parity, doctor, and lifecycle checks passed | native 0.5.0 cache/archive lifecycle verified after reconstructing only released historical trees and indexing 18 trusted versions; 0.5.1 pending | fresh trusted 0.5.0 endpoint runtime passed schema-4 completion with zero continuations; 0.5.1 pending | native 0.5.0 accepted; 0.5.1 requires a new native run |
| Linux | 0.5.1 local source validation is portable; per-commit public CI remains the automated Linux evidence gate | isolated lifecycle is exercised by the public validation workflow | not claimed | CI and isolated lifecycle only; no native desktop claim |

The historical v0.4.9 release evidence and the later native Windows 0.5.0
acceptance remain in `LOCAL_ACCEPTANCE.md`. The table separates current
version-specific evidence from those records and does not infer 0.5.1 Windows
parity from 0.5.0, macOS, or CI.

Do not change a pending cell to verified without preserving the command, result,
plugin version, Codex version, and source/cache parity evidence in the release
acceptance report.

## Hook lifecycle requirements

The plugin defines exactly eight events: `UserPromptSubmit`, `PostToolUse`,
`PreCompact`, `SessionStart`, `SubagentStart`, `SubagentStop`, `Stop`, and
`SessionEnd`.

Plugin installation does not automatically trust Hook commands. Users must
inspect and trust the current definition, then start a fresh task. An old active
task may retain an absolute path into an older versioned cache; the provided
installer therefore retains live historical caches, archives them under the
versioned `cache-archive` contract, and rejects same-version source drift.

## Release gates

Before a public tag:

1. all repository contract and public-tree audits pass;
2. Hook and safe-install regressions pass;
3. the isolated installed lifecycle smoke passes against the standalone cache;
4. macOS source/cache parity and fresh trusted runtime smoke pass;
5. Windows/Linux claims are limited to their actual evidence;
6. remote Git marketplace packaging is checked because the root-level
   marketplace copies the fresh repository metadata into its isolated cache;
7. public CI passes before the release is described as green.
