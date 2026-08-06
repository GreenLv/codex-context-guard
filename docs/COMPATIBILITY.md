# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Context Guard plugin: `0.4.9`
- Private state schema: `3`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## Release status

| Platform | Automated tests | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | v0.4.9 release run: 81 pass, 1 Windows-only skip (82 total) | isolated standalone cache verified | all eight Hooks trusted; real manual `/compact` recovered exact markers | native trusted runtime verified for the release suite |
| Windows | current native Python 3.12.10 run: 82 pass, 1 symlink-permission skip (83 total); v0.4.9 CI on Python 3.10/3.12/3.13 | native isolated standalone cache verified with Codex CLI 0.146.0 | normal persistent trust verified; real manual `/compact` completed backend compaction and recovered both exact markers after `PreCompact` and `SessionStart` | native trusted runtime verified; the isolated CLI used `CODEX_CA_CERTIFICATE` for the Windows trust root |
| Linux | 0.4.9 CI on Python 3.10/3.12/3.13 | isolated lifecycle verified | not claimed | CI and isolated lifecycle only |

The current suite gained one bilingual README parity regression after the
v0.4.9 tag. The macOS row preserves the release-time 82-test result; it does
not imply that the current 83-test suite has been rerun on macOS.

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
