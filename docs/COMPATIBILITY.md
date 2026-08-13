# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Current published Context Guard release: `0.6.3`
- Current source line: `0.7.1` (unreleased candidate)
- Private state schema: `6`
- Proof protocol: `1.0.0`
- Stop protocol: `1.1.0`
- Diagnostic classifier: `2.0.0`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## 0.7.1 candidate status

The candidate retains Stop protocol 1.1.0, classifier 2.0.0, and the exact
eight-Hook wire. Schema 6 adds deterministic verification contracts, hash-only
multimodal assets, and Proof protocol 1.0.0. Enforced contracts reject
successful evidence with the wrong item, subject, surface, freshness,
capability, visual readback, or scope coverage. Unsupported contracts are
auditable `legacy_fallback`, not claims of arbitrary semantic understanding.

Current source acceptance includes schema-5 migration, local/data-URL image
hashing and dimensions, transcript-tail supplementation, no-byte persistence,
Chinese/English positive and negative cases, adversarial wording, wrong-surface
and cross-item rejection, and the anonymized 48-of-70 subset incident replay.
Native Windows 0.7.x acceptance is not claimed; CI cannot substitute for it.

## 0.6.3 release status

The release carries the 0.6.2 schema-5 terminal-control policy and private
control-intent parsing without changing their runtime bytes. Legacy `continue`
remains accepted but cannot force a retry; explicit prompt-bound persistence
and uncheckpointed whole-task completion remain the only correction-turn
gates. Protocol-1.0.0 in-flight controls are discarded on load while the
durable ledger is preserved. The 0.6.3 package adds fail-closed cache lifecycle
repairs for indexed live drift and legacy non-product Git metadata.

The source suites, deterministic 10,000-transition safety lattice, quoted-shell
regressions, complete sibling parity, isolated installation, and scoped native
macOS and Windows fresh-Hook runs pass against the frozen package commits.
Normally trusted private/public identities, without bypass, pass `user_wait`,
completion checkpoint consumption, explicit persistence, terminal legacy
continue, negative controls, and manual schema-5 `/compact` recovery; installed
and isolated source/live/archive lifecycles also pass. CI did not substitute for
either native platform gate. The release is merged into `main`, tagged as
`v0.6.3`, and published as a GitHub Release from that exact validated commit.

Version 0.6.2 was installed during release acceptance before the final
manager lifecycle bytes were frozen. Its cache remains immutable; it was never
tagged or released and is superseded by 0.6.3.

## 0.6.1 release status

| Platform | Source automation | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | local validation passed against frozen private/public runtime inputs | private source/live/archive and installed lifecycle pass; isolated public first-install/archive/no-op/lifecycle and all Context Guard doctor subchecks pass | normally trusted private and public identities, without bypass, pass `user_wait`, completion checkpoint, and manual schema-5 `/compact` recovery | scoped native macOS acceptance; release-source and tag automation are tracked separately |
| Windows | private Hook runtime 107 tests pass with one capability-aware successor-pack symlink skip; manager 16, public-export 3 with one capability skip, parity 5, and four-class share-boundary 20 with one capability skip pass; public validation, privacy audit, Ruff 0.16.1, in-memory compile, and 128 tests pass with one capability-aware symlink skip | frozen private/public runtime inputs match; private source/live/archive, lifecycle, self-test, and strict no-op pass; an isolated 0.5.1 -> 0.6.0 -> 0.6.1 archive/index/lifecycle chain and direct private/public doctor subchecks pass | normally trusted private/public identities with the exact eight-Hook wire each passed raw-receipt `user_wait`, completion checkpoint, and manual schema-5 `/compact` recovery; isolated standard-browser OAuth was logged out and cleaned up; no project writes or continuation occurred | scoped native Windows acceptance with one OS-token capability skip; release-source and tag automation are tracked separately |
| Linux | per-commit public CI is the automated source gate | not yet validated by CI or a native Linux run | not claimed | source CI only; installed lifecycle and native desktop behavior are not claimed |

CI runners validate source behavior and packaging contracts. They do not prove
an installed cache, persisted Hook trust, real `/compact`, or native endpoint
behavior on macOS, Windows, or Linux. The macOS and Windows rows record bounded
native release evidence. Capability-aware skips remain
visible rather than being silently upgraded into platform support claims.
Remaining cells may be upgraded only after the exact frozen private/public
commits, commands, versions, and results are recorded in `LOCAL_ACCEPTANCE.md`.

## Consumed 0.6.0 candidate

Version 0.6.0 was installed for native macOS evaluation but was never tagged or
released. In a normally trusted fresh Codex CLI 0.146.0 Code Mode task,
`PostToolUse` received the successful private command's marker as raw stdout
without a structured exit status. A bare marker is intentionally not a generic
success signal, so the outcome remained unknown and two valid
`stage-disposition` attempts failed closed instead of staging. The default-yield
path kept unresolved requirements pending; the defect did not authorize
completion.

That failed the real fresh-runtime release gate. The installed 0.6.0 live cache
and archive remain immutable recovery artifacts: they must not be overwritten,
deleted, or patched in place, and no `v0.6.0` tag or GitHub Release may be
created. Version 0.6.1 added the final success receipt. The bounded macOS and
Windows runtime paths above underpin the 0.6.3 release; source and tag
automation remain separate evidence.

## Accepted 0.5.1 baseline

| Platform | Automated tests | Installed lifecycle | Fresh trusted Hook runtime | Current claim |
| --- | --- | --- | --- | --- |
| macOS | private 87 Hook tests (86 pass, 1 Windows-only skip), private combined 111 tests, and public standalone 108 tests (107 pass, 1 skip), repository validation, public-tree audit, complete share-boundary/parity, Ruff 0.16.1, and source compilation pass | private persistent 0.5.1 cache/archive and isolated public 0.5.1 install/no-op/archive/lifecycle verified with Codex CLI 0.146.0 | fresh private-identity task loaded classifier 1.0.1 without trust bypass and ended a user-dependent handoff with zero continuations and no project writes | native private 0.5.1 runtime plus isolated public lifecycle verified; fresh public-identity Hook trust was not repeated |
| Windows | native 0.5.1 source and installed-cache Hook suites each ran 87 tests with one capability-aware symbolic-link skip; all 16 manager, 3 export, 5 parity/share-boundary, and 108 public tests with one skip passed with repository/privacy/Ruff gates | source/cache parity, isolated same-version first-adoption, 19-version live/archive audit, installed lifecycle, eight-Hook self-test, unified validation, and doctor verified with Python 3.12.10 and Codex CLI 0.146.0 | fresh normally trusted 0.5.1 runtime returned the conditional user handoff once with classifier outcome `allow_user_handoff`, derived open items, zero continuations, and no project writes | native private 0.5.1 runtime plus isolated public lifecycle verified; fresh public-identity Hook trust was not repeated |
| Linux | 0.5.1 local source validation is portable; per-commit public CI remains the automated Linux evidence gate | isolated lifecycle is exercised by the public validation workflow | not claimed | CI and isolated lifecycle only; no native desktop claim |

The historical v0.4.9 and native Windows 0.5.0 evidence also remain in
`LOCAL_ACCEPTANCE.md`. The accepted 0.5.1 Windows claim is based on a separate
same-version native run rather than an inference from 0.5.0, macOS, or CI; it
does not validate the 0.6.1 release line.

Do not change a pending cell to verified without preserving the command, result,
plugin version, Codex version, and source/cache parity evidence in the release
acceptance report.

## Hook lifecycle requirements

The plugin defines exactly eight events: `UserPromptSubmit`, `PostToolUse`,
`PreCompact`, `SessionStart`, `SubagentStart`, `SubagentStop`, `Stop`, and
`SessionEnd`.

Plugin installation does not automatically trust Hook commands. Users must
inspect and trust the current definition, then start a fresh task. The 0.6.x
line adds a private CLI/state protocol but no Hook event, matcher, or Codex Hook
payload field. An old active task may retain an absolute path into an older
versioned cache; the provided installer therefore retains live historical
caches, archives them under the versioned `cache-archive` contract, and rejects
same-version source drift. A 0.6.1 install must preserve every 0.5.x and 0.6.0
live cache and archive. Open tasks that still reference an absolute 0.6.0 path
continue on those immutable bytes; only a fresh task may load 0.6.1.

## Historical 0.6.1 release gates

Version 0.6.0 is ineligible for a public tag. Before any 0.6.1 tag:

1. all repository contract and public-tree audits pass;
2. schema-5 protocol regressions pass for all four dispositions, default yield,
   checkpoint priority, control replacement, anti-forgery boundaries, the
   two-continuation cap, migration, and compact recovery;
3. shared-core parity binds the exact frozen private and public commits;
4. the isolated installed lifecycle smoke passes against a new 0.6.1 cache
   while all 0.5.x and 0.6.0 live/archive trees remain intact, including a
    second strict no-op run;
5. the accepted macOS source/install/archive, private/public trust,
   `user_wait`, checkpoint, and manual compact/recovery evidence is preserved;
   the complete native Windows source, installed, fresh-trust, disposition,
   doctor, archive, raw-receipt checkpoint, and real compact/resume evidence is
   recorded separately;
   bare-marker and failure-first negative cases remain rejected, and CI is not
   substituted for either native run;
6. remote Git marketplace packaging is checked because the root-level
   marketplace copies the fresh repository metadata into its isolated cache;
7. public CI and HOL pass on the final frozen public commit; and
8. tag and GitHub Release creation receive separate explicit authorization;
   that authorization was granted on 2026-08-11 for the exact accepted 0.6.1
   release commit after all preceding gates pass.
