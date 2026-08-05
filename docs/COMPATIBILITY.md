# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Context Guard plugin: `0.4.8`
- Private state schema: `3`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## Candidate status

| Platform | Automated tests | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | 80 pass, 1 Windows-only skip (81 total); corrected public CI pending | isolated standalone cache verified | standalone manual trusted `/compact` still pending | local candidate verified except standalone fresh trusted runtime |
| Windows | 0.4.8 rerun required after lock-race fix | synthetic test required | native 0.4.8 run pending | no native parity claim; final CI evidence pending |
| Linux | required in CI | synthetic test required | not claimed | CI and isolated lifecycle only |

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
4. macOS source/cache parity and fresh no-bypass runtime smoke pass;
5. Windows/Linux claims are limited to their actual evidence;
6. remote Git marketplace packaging is checked for repository metadata because
   the local root-level marketplace copies the whole fresh repository into the
   isolated cache under Codex CLI 0.146.0;
7. public CI passes before the final release is described as green.
