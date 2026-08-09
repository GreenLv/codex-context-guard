# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Context Guard plugin: `0.4.16`
- Private state schema: `3`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## Release status

| Platform | Automated tests | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | v0.4.16: 78 Hook tests pass, 1 Windows-only skip; standalone total 90 pass, 1 skip; public CI passes Python 3.10/3.12/3.13 plus Ruff | private and isolated standalone 0.4.16 caches verified with Codex CLI 0.146.0 | a trusted fresh task returned the bounded local-commit / deferred-push status once with zero continuations | native 0.4.16 scoped-phase and lifecycle behavior verified |
| Windows | public 0.4.16 CI passes 91 tests, validation, audit, Ruff, and compilation on Python 3.10/3.12/3.13; 0.4.13 remains the latest native endpoint verification | native private and standalone 0.4.16 caches not yet verified on the Windows endpoint | fresh trusted 0.4.16 endpoint runtime pending | CI runner coverage is accepted as automated source evidence only; do not infer native endpoint parity from it |
| Linux | public 0.4.16 CI passes Python 3.10/3.12/3.13, including 91 tests, validation, audit, Ruff, and compilation | isolated lifecycle covered in CI | not claimed | CI and isolated lifecycle only |

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
installer therefore preserves older caches during upgrades and rejects
same-version source drift.

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
