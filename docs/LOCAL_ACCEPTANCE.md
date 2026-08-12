# Local Release Acceptance

This document records local and remote acceptance evidence for standalone
Context Guard. The current published release is `0.6.1`; verified source line
`0.6.3` is merged into `main` but remains untagged and unreleased;
accepted `0.5.1` and historical `0.5.0`/`0.4.9` evidence remains below.

## 0.6.3 candidate acceptance (macOS and Windows accepted; merged, not tagged)

Version 0.6.3 keeps schema 5, advances the Stop protocol to 1.1.0, retains
classifier 2.0.0 and the exact eight-Hook wire, and makes the legacy
`continue` disposition advisory. The candidate must prove that a terminal
control mismatch can only yield with pending work preserved; it cannot request
another turn unless the hash-verified prompt independently activates explicit
persistence. Private-control detection is also restricted to recognized shell
execution and quote-aware operator parsing.

Local source evidence must include the complete private/public suites, 10,000
deterministic control transitions, the historical user-handoff mismatch replay,
quoted-search and non-shell negative cases, schema-5 protocol-attempt
invalidation, four-class sibling parity, public privacy/identity validation,
Ruff 0.16.1, compilation, and isolated first-install/no-op/lifecycle checks.

Version 0.6.2 was consumed by a real candidate installation before the final
cache-lifecycle manager bytes were frozen; it remains immutable, untagged, and
unreleased. Frozen 0.6.3 package inputs are private
`7809c42f65516e14a1f31c59c3ade8d0e2792bff` and public
`d3df09b0ba92797ca03a26a856b6669c3f52b54c`.

Scoped native macOS acceptance passes against those immutable package trees:

- private validation passes 113 Hook tests with one platform skip, 21 manager
  tests, the unified validator, export/parity/boundary gates, installed
  eight-Hook self-test, and lifecycle smoke;
- public validation passes repository, tracked-tree privacy, four-class parity,
  commit-identity, Ruff 0.16.1, compilation, installed self-test/lifecycle, and
  145 tests with one platform skip;
- default and isolated private/public installs preserve trusted
  source/live/archive bytes, consumed 0.6.2 caches, upgrade and fresh-install
  paths, and strict second no-ops; and
- normally trusted private and public identities, without bypass, each pass
  real `user_wait`, completion checkpoint consumption, and manual schema-5
  `/compact` recovery. Both compacted states retain pending requirements with
  `integrity=ok`, `trigger=manual`, zero continuation attempts, and a native
  `compacted` rollout event.

Public PR #8 at the public package head passes the nine-job Ubuntu/macOS/Windows
Python 3.10/3.12/3.13 CI matrix, HOL Plugin Scanner, and plugin-scanner. Native
Native Windows acceptance independently passes against the same frozen inputs:
113 private and 145 public tests (one capability-aware symlink skip each),
manager/export/parity/boundary and public privacy/identity gates, Ruff 0.16.1,
compilation, installed lifecycle and eight-Hook self-tests, 0.6.1 -> 0.6.2 ->
0.6.3 repair-before-archive chains, and strict second no-ops. Normally trusted
private/public identities pass legacy continue, `user_wait`, completion,
explicit persistence, malformed-control isolation, and manual schema-5
`/compact` recovery. CI did not substitute for these native checks. This
candidate section did not authorize merge, tag, or Release; after the native
gate passed, the 0.6.3 code was merged into `main`, while tag and Release
remain separate publication actions.

## 0.6.1 native acceptance on macOS (2026-08-11)

The frozen runtime code inputs are private commit
`4ddac0d402d0efb520db41fe9cd84152adc560b4` and public commit
`42a2e57b80a9f36704ba8baf58db9c036615c3d2`. Later documentation-only
successors do not replace those runtime inputs.

Native macOS acceptance passed the scoped local and fresh-runtime
gates:

- the private runtime passed 107 Hook regressions with one Windows-only skip,
  16 manager regressions, three public-export regressions, five parity
  regressions, the unified skill validator, and the complete four-class share
  boundary;
- the public product passed repository validation, tracked-tree privacy audit,
  complete boundary/parity validation, Ruff 0.16.1, in-memory compilation, and
  128 tests with one Windows-only skip;
- private 0.6.1 source/live/archive bytes match, the installed private Hook
  suite, eight-Hook self-test, and schema-5 lifecycle smoke pass, and every
  Context Guard doctor subcheck passes. The current whole private-repository
  doctor separately reports one unrelated installed-skill drift and one known
  noninteractive warning;
- an isolated private 0.5.1 to 0.6.0 to 0.6.1 chain and an isolated public
  0.6.1 first install both preserved trusted archives, passed lifecycle smoke,
  and ended in a strict same-version no-op; and
- normally trusted private and public identities, run without a trust bypass,
  each passed `user_wait`, a completion checkpoint, and real manual schema-5
  `/compact` recovery. Base/profile trust remained isolated at eight private
  versus eight public Hook keys.

The public compact record ended with a manual compaction while retaining its
pending requirement and acceptance items. Native Windows acceptance is recorded
separately below. PR/main/tag automation is verified independently on the exact
release commit and does not replace either native claim.

## 0.6.1 native acceptance on Windows (2026-08-11)

Windows acceptance used Python 3.12.10 and Codex CLI 0.146.0 against frozen
private runtime commit `4ddac0d402d0efb520db41fe9cd84152adc560b4`, frozen
public runtime commit `42a2e57b80a9f36704ba8baf58db9c036615c3d2`, and the
docs-only public predecessor `c4a85027e01119e22d2a2c96eb08a4304e256cbc`. The
docs-only predecessor changed no runtime input.

Source validation passed in both repositories. The private Hook suite ran 107
tests with one capability-aware successor-pack symlink skip under a normal
Windows token; manager 16, public-export 3 with one capability skip, parity 5,
and four-class share-boundary 20 with one capability skip also passed. The
public repository passed its repository validator, privacy audit, Ruff 0.16.1,
in-memory compile, and 128 tests, of which 127 passed and one successor-pack
symlink case was skipped for the same OS-token capability boundary.

A disposable trusted-archive sequence exercised 0.5.1 -> frozen 0.6.0 -> 0.6.1
with matching SHA-256 live/archive/index evidence, installed lifecycle checks,
and a final strict no-op. The default private 0.6.1 installation preserved the
existing versioned history, did not fabricate a real 0.6.0 installation, and
passed source/live/archive parity, self-test, lifecycle, and no-op checks.
Direct doctor results were `17 ok / 1 idle / 2 notes / 0 warn / 0 fail` for the
private installation and `17 ok / 1 idle / 1 note / 0 warn / 0 fail` for the
isolated public installation.

Fresh private and public identities each ran the exact eight-Hook wire with
normal trust and no bypass. Both paths passed a raw-receipt `user_wait`, a
completion checkpoint, and manual schema-5 `/compact` recovery with
`integrity.status = ok`, zero recorded continuation, and no project writes.
Because the device-code beta setting was unavailable in the web UI, the public
identity used the standard browser OAuth flow; that isolated identity was then
logged out and its temporary home removed while the default login and
configuration remained intact.

The successor-pack symlink skip and a constrained-profile warning are recorded
as capability evidence, not functional failures. PR/main/tag automation remains
a separate release gate rather than native Windows evidence.

The public 0.6.1 branch began at version-only commit
`180c94c0e86503a09792af5fc04c16df21ca920f`; the private branch began at
version-only commit `28428743bfebde901b9d7be8e3392bfd5ea824bc`. Neither
commit contains the complete 0.6.1 runtime candidate or may be used as a frozen
acceptance SHA.

The 0.6.1 release contract is:

- plugin `0.6.1`, private state schema 5, Stop protocol 1.0.0, and diagnostic
  classifier 2.0.0;
- one exclusive, idempotent, replaceable turn-bound `staged_control`, containing
  either a verified checkpoint or `continue`, `user_wait`, `external_wait`, or
  `deferred`; `complete` is checkpoint-derived and is not a disposition;
- `stage-disposition` performs a private precheck and `PostToolUse` performs the
  authoritative write after command/session/turn/token/data-directory/marker/
  outcome verification. A structured tool failure or nonzero status takes
  priority. For raw stdout, the successful CLI emits the exact hash marker and
  then a final standalone `Script completed` receipt; a bare marker remains
  rejected;
- private status, checkpoint, and disposition commands cannot create successful
  requirement-closing evidence;
- default safe yield keeps unresolved requirements pending; only a valid
  checkpoint, an uncheckpointed high-confidence whole-task completion claim,
  explicit user persistence, or staged `continue` changes the normal Stop path,
  while a genuine user/external wait may still yield under persistence;
- classifier action ownership is diagnostic rather than the primary
  continuation authority; and
- the exact eight Hook events and their Codex payload shapes remain unchanged.

The 0.6.1 release preserves the frozen runtime inputs and accepted native
evidence through the following gates:

1. preservation of the accepted local suites, migrations, stale-control
   invalidation, mutually exclusive and replaceable controls, all
   disposition/Stop priorities, classifier blind spots, forged/failed control
   commands, control-evidence isolation, and the bounded continuation cap;
2. preservation of the accepted isolated upgrade/no-op, installed lifecycle,
   source/cache/archive, normal-trust, raw-receipt, checkpoint, and compact
   evidence without changing frozen runtime bytes;
3. preservation of the recorded native Windows source, installed, archive, and
   fresh-session evidence, including the explicit disposition of the
   normal-token successor-pack symlink capability; and
4. final-commit public PR/main CI and HOL plus tag CI, recorded as source
   automation rather than installed-runtime or native-platform acceptance.

Requirement-to-evidence semantic relevance is not a 0.6.x acceptance item. It
remains benchmark-first research for a possible 0.7.0 only after positive,
negative, adversarial, multilingual, false-acceptance, false-rejection, and
abstention thresholds are approved.

## 0.6.0 unreleased failed candidate

Version 0.6.0 established the schema-5 protocol candidate at private commit
`288398b70533f69c1a2e1ca96b81cbf3a8fe4fdd` and public commit
`bb0f8622ce829aa3b33875df26c8bbc2ec1ad8e9`. It was never tagged or released.

During native macOS evaluation with normally trusted Hooks and Codex CLI
0.146.0 Code Mode, the successful inner private command reached `PostToolUse`
as raw stdout containing only its hash marker, without a structured exit code.
The generic outcome classifier correctly treated the bare marker as unknown, so
two valid disposition requests, including `user_wait`, were rejected instead of
staged. The default safe-yield behavior retained pending requirements, but the
fresh-runtime protocol gate failed.

Because 0.6.0 had already been installed, its live cache and archive are
immutable and its version number is consumed. They must not be overwritten,
deleted, or patched in place, and no `v0.6.0` tag or GitHub Release may be
created. Native Windows source, installed, fresh-trust, disposition, and compact
acceptance for 0.6.0 was not completed and is not inferred from CI or 0.5.1.

## 0.5.1 local acceptance on macOS (2026-08-10)

- State schema remains 4 and the stable Stop outcome/action interface is
  unchanged. Classifier 1.0.1 separates user-dependent assistant futures from
  independent or parallel assistant work, while persisted `open_items` is
  normalized from current requirement and acceptance status.
- Private source passes 87 Hook regressions (86 pass and one Windows-only
  skip), 16 safe-install regressions, three public-export regressions, and five
  sibling parity/share-boundary regressions: 111 tests in total with one skip.
- The standalone public tree passes repository validation, privacy audit,
  complete four-class share-boundary coverage, shared-core parity, Ruff 0.16.1,
  source compilation, and 108 tests (107 pass and one skip).
- The private 0.5.1 installation preserved all historical live and archived
  caches, added an indexed immutable 0.5.1 archive, passed strict no-op audit,
  source/cache parity, the installed 87-test Hook suite, the eight-Hook
  self-test, and the installed schema-4 lifecycle smoke.
- A disposable standalone Codex home installed public 0.5.1, created and
  audited its trusted archive, passed a strict no-op rerun, and completed the
  installed lifecycle smoke.
- A fresh read-only private-identity task loaded the installed 0.5.1 skill and
  Hook without trust bypass. Its conditional login/unlock handoff produced
  classifier 1.0.1 outcome `allow_user_handoff`, `integrity=ok`, zero
  continuations, no checkpoint, derived open items for the pending contract,
  and no project writes.
- Native Windows 0.5.1 acceptance was completed separately in the section below;
  it is not inferred from macOS or CI.

## 0.5.1 native acceptance on Windows (2026-08-10)

- Native Windows used Python 3.12.10 and Codex CLI 0.146.0. Private source and
  installed-cache copies each ran all 87 Hook regressions with one capability-
  aware symbolic-link skip; all 16 manager, three public-export, five parity/
  share-boundary, and 108 public regressions with one skip passed alongside
  repository validation, privacy audit, Ruff, and unified validation.
- A disposable standalone home installed public 0.5.1, deliberately removed
  only its disposable archive, then proved the locked same-version first-
  adoption path. The following read-only run was a strict no-op and preserved
  exact source/cache parity without an in-place refresh.
- The installed runtime retained 19 indexed live and trusted archive versions
  through 0.5.1, including both 0.5.0 and 0.5.1. Archive audit, installed
  lifecycle, the eight-Hook self-test, source/cache parity, and doctor all
  passed.
- A fresh no-bypass task reviewed and trusted the installed 0.5.1 Hooks through
  the normal flow, made no project-file change, and returned the requested
  conditional user handoff once. Schema 4 retained `integrity=ok`; classifier
  1.0.1 returned `allow_user_handoff`, preserved the pending derived open items,
  and produced zero continuations and no completion checkpoint.

## 0.5.0 native acceptance on Windows (2026-08-10)

- Native Windows used Python 3.12.10 and Codex CLI 0.146.0. Source and installed
  caches each ran all 84 Hook regressions with one capability-aware symbolic-
  link skip; 11 safe-install regressions, three public-export regressions,
  three sibling parity regressions, the eight-Hook self-test, and the installed
  lifecycle smoke passed.
- The first archive preflight correctly failed closed because an already-current
  byte-identical 0.5.0 live cache had no trusted archive index and older live
  caches were absent. Seventeen historical trees were reconstructed only from
  matching released Git commits; together with the live 0.5.0 tree, 18 trusted
  versions passed SHA-256 archive audit.
- The public sibling was fast-forwarded to the accepted 0.5.0 source, and native
  private/public shared-core parity passed. A fresh no-bypass task loaded the
  installed 0.5.0 Hook, consumed a schema-4 checkpoint with `integrity=ok`, and
  ended with zero continuations and no project writes.
- This evidence closes the Windows 0.5.0 pending claim only. It does not prove
  the new 0.5.1 classifier or first-adoption manager behavior on Windows.

## 0.5.0 local acceptance on macOS (2026-08-09)

- State schema 4, Stop classifier 1.0.0, bounded decision diagnostics, and the
  durable cache-archive lifecycle are present in the exact public/private
  shared core.
- Private source passes 84 Hook regressions (83 pass and one Windows-only
  skip); the Context Guard combined suite passes 101 tests with the same skip.
- The standalone public tree passes repository validation, privacy audit,
  sibling-core parity, Ruff 0.16.1, and 100 tests (99 pass and one skip).
- The private 0.5.0 installation archived and verified live versions 0.4.12,
  0.4.13, 0.4.15, 0.4.16, and 0.5.0. The installed Hook suite, eight-Hook
  self-test, schema-4 lifecycle smoke, and read-only archive audit pass.
- A disposable standalone Codex home installed public 0.5.0, created its
  trusted archive, passed a strict no-op rerun, and completed the schema-4
  installed lifecycle smoke.
- A fresh read-only task loaded private-identity 0.5.0 without Hook trust
  bypass, emitted an authoritative successful check, staged and consumed R001
  and A001, ended with `integrity=ok`, zero open items, zero continuations, and
  no project file writes. Fresh public-identity trust was not repeated.
- The macOS sync doctor reports zero sync failures and one aggregate warning;
  the underlying non-interactive Codex doctor warning is `TERM=dumb`.
- Public source commit `d252b0e` passes the nine-job Ubuntu/macOS/Windows
  Python 3.10/3.12/3.13 CI matrix (run `31314327607`) and the mandatory HOL
  scan (run `31314327528`). Native Windows 0.5.0 installation/runtime was still
  pending during this macOS run and was accepted later in the section above;
  CI runner evidence was not used as a substitute.
- No `v0.5.0` tag or GitHub Release is part of this acceptance run.

## Historical 0.4.9 release acceptance

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

Version 0.6.0 is consumed, unreleased, untagged, and ineligible for a tag or
GitHub Release. The 0.6.1 tag and Release received explicit authorization on
2026-08-11. Only the exact final commit that preserves the accepted macOS and
Windows runtime evidence, passes all local and remote packaging gates, passes
PR/main CI and HOL, and then passes tag CI may be published. Compatibility
wording must remain bounded by observed evidence.
