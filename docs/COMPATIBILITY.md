# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Context Guard plugin: `0.5.0`
- Private state schema: `4`
- Stop classifier: `1.0.0`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## Release status

| Platform | Automated tests | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | private 84 Hook tests (83 pass, 1 Windows-only skip), private combined 101 tests, and public standalone 100 tests (99 pass, 1 skip), repository/audit/parity/Ruff gates pass | private persistent 0.5.0 cache/archive and isolated public 0.5.0 install/no-op/archive/lifecycle verified with Codex CLI 0.146.0 | fresh private-identity task loaded the 0.5.0 skill/Hook without trust bypass, consumed schema-4 checkpoint, and ended with zero continuations and no project writes | native private 0.5.0 runtime plus isolated public lifecycle verified; fresh public-identity Hook trust was not repeated |
| Windows | 0.5.0 public CI pending; 0.4.13 remains the latest native endpoint verification | native 0.5.0 cache/archive lifecycle pending | fresh trusted 0.5.0 endpoint runtime pending | CI evidence will not establish native endpoint parity |
| Linux | 0.5.0 public CI pending | isolated lifecycle pending CI | not claimed | CI and isolated lifecycle only |

The historical v0.4.9 release evidence remains in `LOCAL_ACCEPTANCE.md`. The
table above separates current version-specific evidence from that release
record and does not infer cross-platform parity.

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
