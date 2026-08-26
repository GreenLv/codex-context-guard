# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Current published Context Guard release: `0.8.8`
- Current source line: `0.8.9` (`Unreleased` source candidate)
- Private state schema: `7`
- Proof protocol: `1.0.0`
- Stop protocol: `1.1.0`
- Execution protocol: `1.0.0`
- Diagnostic classifier: `2.3.1`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## 0.8.9 source-candidate status

Version 0.8.9 narrows the Stop privacy classifier without weakening private
control protection. Canonical redaction placeholders and short human-readable
quoted token examples contain no private control value, so those explanatory
forms no longer cause a continuation. Whitespace is removed before token-shape
comparison; padding or splitting a private-token-shaped value therefore remains
fail-closed. Private directory/session/turn bindings, control invocations,
internal markers, and serialized control structures also remain fail-closed.
Schema 7, Proof protocol 1.0.0, Stop protocol 1.1.0, Execution protocol 1.0.0,
and the eight-Hook wire are unchanged.

## 0.8.8 release status

Version 0.8.8 changes Hook interpreter selection without changing the eight
events, payloads, schema, protocols, classifier, or private-state behavior.
The POSIX launcher probes versioned Python 3 commands before generic names;
the Windows launcher validates generic commands first, then versioned commands
and `py -3.x` fallbacks.
Both require Python 3.10+ and preserve Hook stdin/stdout/stderr.

Native macOS 0.8.7 deterministic install and lifecycle gates passed, but a
newly trusted interactive Codex CLI 0.149.0 task exposed that bare `python3`
resolved to `/usr/bin/python3` 3.9.6 even though Python 3.12.2 was available
later on `PATH`. `UserPromptSubmit` and `Stop` exited with code 2; direct
reproduction reached the runtime's Python 3.10+ guard. That fresh trusted-Hook
gate therefore failed and motivated this candidate. The candidate now passes
the macOS source gates and an isolated install/no-op/read-only/self-test/smoke
chain. A fresh interactive Codex CLI 0.149.0 task then trusted all eight Hooks;
`UserPromptSubmit` and `Stop` ran successfully, the fixed reply returned, and
private state was written with mode `0600`.

Native Windows applied exact candidate
`40987d48d6a6f7a8ea8b3ae6e468c472170748a4` through the pinned consumer into
the real Codex home. The managed upgrade, strict second no-op, read-only
readback, eight-Hook self-test, lifecycle smoke, PowerShell launcher, and fresh
interactive trust all passed. Historical 0.8.3/0.8.5/0.8.6/0.8.7 live trees
stayed byte-wise unchanged. The new staging/live/archive trees retained 41
files without Git or bytecode residue, and all 15 product files match across
source, staging, live cache, and archive. The exact downstream acceptance
commit and its CI passed separately. PR, main, tag, Release, and downstream
final-pin evidence remain distinct publication surfaces.

## 0.8.7 release status

Version 0.8.7 changes only managed cache-upgrade preservation. Product parity
continues to ignore bytecode and other non-product files, and trusted archives
continue to authenticate only product bytes. Before a Codex refresh that may
replace the complete cache root, the installer separately snapshots any
all-file difference between an indexed historical live tree and its archive.
The snapshot is path- and SHA-256-bound, lives outside the replaceable root,
and is removed only after the same historical live path is restored exactly.

An interrupted snapshot remains recoverable. Read-only inspection reports it
without writing; a later managed apply restores it before inspecting current
plugin state. Invalid transaction metadata, embedded Git metadata, symlinks,
or product drift fail closed before `codex plugin add`.

Native macOS source validation passes the repository/privacy gates, 206 tests
with two capability-aware skips, eight-Hook self-test, Ruff, external-cache
compilation, and diff checks. A real Codex CLI 0.149.0 isolated upgrade creates
an actual 339,172-byte `.pyc` in the 0.8.6 live tree, then applies candidate
implementation commit `285c3905bcf20a1c326761cfe719d02c4dcf06c0`. The old live all-file
SHA-256 snapshot remains unchanged through upgrade, no-op, read-only readback,
and the new installed smoke; its trusted archive remains product-only. The new
staging/live/archive trees match, and the smoke runs without an outer bytecode
guard without changing the new live snapshot. Exact candidate commit
`d91a663af20623c1a38d69e3a062903f9e30e673` passes the 12-job PR CI matrix,
HOL Scanner, and plugin scanner.

Native Windows acceptance installed that exact candidate in the real Codex
home. All pre-existing 0.8.3, 0.8.5, and 0.8.6 historical live-tree file/hash
snapshots remained unchanged across apply; the already-lost 0.8.5 `.pyc`
remained absent rather than being recreated. The new smoke left the 0.8.7
all-file snapshot unchanged, and all 13 product files match across source,
staging, live cache, and archive with no forbidden residue. The exact downstream
acceptance commit and its CI passed separately.

## 0.8.6 release status

Version 0.8.6 changes only the installed lifecycle smoke. Its final validation
step directly imports the installed runtime with bytecode writing disabled in
the smoke process itself, so callers do not need an outer
`PYTHONDONTWRITEBYTECODE=1` or `python -B` guard to keep the immutable plugin
root clean. The setting is restored after the import.

Native Windows 0.8.5 passed the managed upgrade, no-op, read-only, self-test,
lifecycle assertions, and manifest-parity gates, then correctly stopped when
the old smoke wrote one ignored `.pyc` artifact into the live cache. Ignoring
bytecode in product manifests prevents false source drift; it does not make an
acceptance tool's live-cache mutation acceptable. Version 0.8.6 adds an
environment-independent no-bytecode regression. Native Windows 0.8.6 later
failed during managed apply because the Codex refresh replaced the cache root
and the product-only archive restoration omitted that historical `.pyc`.
No-op, smoke, and parity were not continued. This is the distinct preservation
defect addressed by the 0.8.7 candidate; it is not inferred away by macOS or CI.

Native macOS source validation passes the repository/privacy gates, 202 tests
with two capability-aware skips, the eight-Hook self-test, Ruff, compilation,
and diff checks. An exact-candidate isolated install passes a strict second
no-op, installed self-test, source/staging/live/archive parity, and the full
smoke without an outer bytecode guard while preserving an all-file SHA-256
snapshot and leaving no Git or bytecode residue. Publication and downstream
native acceptance remain separate evidence surfaces.

## 0.8.5 release status

Version 0.8.5 keeps every runtime, schema, protocol, classifier, and Hook
contract from 0.8.4. It extends only marketplace migration recognition for
commit-addressed pinned consumers: a previous checkout or sanitized staging
root is eligible only when it is a direct child of the managed
`CODEX_HOME/upstreams/context-guard` directory, has the exact commit/staging
name shape, and declares the same plugin repository as the current source.

Version 0.8.4's direct-checkout and isolated installation paths pass, but a
real pinned downstream 0.8.3-to-0.8.4 pin raise exposed that the old and new
immutable checkout paths differ. Version 0.8.5 corrects that limitation,
fails closed for unrelated roots, and preserves read-only no-write behavior.
An exact-commit isolated consumer migrated from 0.8.3,
preserved both versioned cache/archive sets, passed installed lifecycle and
self-test, then completed a strict no-op and normal read-only readback.
Default-home acceptance, CI, tag metadata, and GitHub Release metadata remain
separate evidence surfaces.

## 0.8.4 release status

Version 0.8.4 changes the installer and cache lifecycle without changing the
eight Hook events, schema 7, execution protocol 1.0.0, Proof protocol 1.0.0,
Stop protocol 1.1.0, or classifier 2.3.0. The managed installer registers the
marketplace at a sanitized, manifest-verified staging copy rather than at the
immutable Git checkout, so a Codex cache refresh cannot copy checkout `.git`
metadata into the live versioned cache.

An existing checkout registration requires one managed `--apply`. That run
atomically creates or refreshes staging, repoints the marketplace, and repairs
an affected live cache only from its trusted archive. A non-apply check remains
read-only and reports the exact `--apply` remediation. Historical caches,
archives, task ledgers, and private plugin data are preserved.

Native Windows real-CLI testing covers the original defect, fresh registration,
checkout-to-staging migration, already-embedded `.git` repair, strict no-op,
and read-only diagnosis. Native macOS independently covers the public source
gates and an isolated 0.8.4 install/no-op/lifecycle chain. CI, HOL, a downstream
consumer pin, a default-home migration, tag metadata, and GitHub Release
metadata remain separate evidence surfaces.

## 0.8.3 release status

Version 0.8.3 can keep an adopted project's instruction sources and execution
plan aligned across a long task. It records the user as the source of task and
write authority, `AGENTS.md` or selected Skills as workflow sources, Codex Plan
as a revisable execution arrangement, and tool/file/image/public readback as
factual evidence. A workflow source, model plan, or successful tool result
cannot expand the user's authority.

For example, an adopted publishing Skill can be bound by exact source hash,
while an optional Codex Plan binding records the current plan meaning. If the
Skill or plan later changes, the previous binding is marked for review rather
than silently reused. The root-user-only `context-guard adopt` control accepts
only a deterministic, project-relative, hash-only manifest; ordinary prose
cannot activate it. Internally, schema 7 stores bounded source metadata,
phases, gates, authorization candidates, drift, coverage, ticket namespaces,
unified-exec sessions, and delegated actors.

The Hook surface remains the same eight events. The release records and restores
the adopted relationships and checks them at completion; it adds no
`PreToolUse`, tool interception, ticket reservation in normal lifecycle,
commit/publish action, or authority for uncovered surfaces. Source validation,
privacy audit, isolated install, native macOS acceptance, downstream consumer
pinning, CI, tag, and GitHub Release are separate claims.

Native macOS source validation passes the repository contract and privacy
audits, 192 tests with two capability-aware skips, the source self-test, Ruff
0.16.1, compilation, and `git diff --check`. An isolated Codex CLI 0.149.0 home
passes first install, source/cache parity, strict second-run no-op, installed
schema-7 lifecycle smoke, and the installed eight-Hook self-test. A downstream
configuration consumer independently verifies the exact public Git commit and
manifest, installs 0.8.3 into the default home, enables the public identity,
disables the old private identity without deleting its caches, and passes a
strict second no-op plus source self-test.

Native Windows source validation passes with Python 3.12.10: the repository
contract and tracked-tree privacy audits, 192 tests with one capability-aware
symbolic-link skip, the source self-test, Ruff 0.16.1, compilation, and
`git diff --check`. The Windows consumer independently verifies the exact
public commit and manifest, installs `context-guard@codex-context-guard` 0.8.3,
passes source/cache/archive parity, installed schema-7 lifecycle and eight-Hook
self-tests, and a second strict no-op. The old private identity is disabled
without deleting its versioned live/archive cache set. These native macOS and
Windows results do not substitute for a fresh trusted Hook task, CI, tag, or
GitHub Release.

A normally trusted fresh Codex CLI 0.149.0 task on macOS, with no trust bypass
and Python 3.12.2 selected on `PATH`, loaded the public 0.8.3 eight-Hook runtime.
Its root-user adoption control activated the schema-7 contract with
`integrity=ok`; the deterministic candidate became active, the natural-language
candidate remained non-authoritative, and no action ticket or denial was
created. Main and tag CI/HOL, tag metadata, and GitHub Release metadata remain
separate publication evidence.

## 0.7.7 release status

The 0.7.7 release keeps schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0,
Python 3.10+, and the exact eight-Hook wire. It corrects false subjects derived
from slash-delimited prose and URL fragments, narrows generic Chinese apply
wording so it does not imply a UI surface, and treats a valid structured
`view_image` image data URL as successful visual evidence. Classifier metadata
is 2.2.1.

Native Windows validation passes repository validation, the tracked-tree privacy
audit, sibling parity, 170 tests with one capability-aware skip, the eight-Hook
source self-test, Ruff 0.16.1, compilation, and `git diff --check`. An isolated
Codex CLI 0.146.0 install passes first install, source/cache parity, strict
second-run no-op, the installed eight-Hook self-test, and lifecycle smoke.
Native macOS passes the same public source gates with two capability-aware
skips, the source self-test, and the same isolated install/no-op/lifecycle
chain. A normally trusted public fresh-CLI Hook task was not repeated for this
patch. Main and tag CI/HOL remain separate source-automation evidence and do
not substitute for either native result.

## 0.7.6 release status

The 0.7.6 release keeps schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0,
and the exact eight-Hook wire. Classifier 2.2.0 distinguishes current-task
completion assertions from hypotheticals, attributed quotations, framed
examples, questions, and trailing negations, while recognizing plural and
quantified completion claims and explicit first-person reporting. Versions
0.7.4 and 0.7.5 bound negation to the latest explicit assistant-future segment,
so an authorized action after “but I will ...” remains visible, and
review/configuration verbs are not discarded merely because they mention
documentation. The Hook entry now fails closed on Python older than 3.10.

The shared runtime and its regression contract have been synchronized into this
public source tree. Scoped native Windows verification for this public commit
passes repository validation, the tracked-tree audit, sibling parity, the 168
test suite with one capability-aware skip, Ruff 0.16.1, compilation, and an
isolated first-install/strict-no-op/installed-lifecycle chain. Native macOS
passes the public repository gates, 168 tests with two capability-aware skips,
the source self-test, and the same isolated install/no-op/lifecycle chain. A
normally trusted public fresh-CLI Hook task was not repeated for this patch.
Main and tag CI/HOL remain separate source-automation evidence and do not
substitute for either native result.

## 0.7.3 release status

The release retains Stop protocol 1.1.0, classifier 2.0.0, and the exact
eight-Hook wire. Schema 6 adds deterministic verification contracts, hash-only
multimodal assets, and Proof protocol 1.0.0. Enforced contracts reject
successful evidence with the wrong item, subject, surface, freshness,
capability, visual readback, or scope coverage. Unsupported contracts are
auditable `legacy_fallback`, not claims of arbitrary semantic understanding.

The 0.7.3 compatibility gate additionally covers ordinary shell/search text
containing private subcommand names, qualitative `all`/`完整` wording that must
fall back, prompt-derived scope cardinality, once-per-prompt transcript scans,
and recovery clipping that cannot remove the completion rule. It also proves
that denied or out-of-scope visual mutation wording does not create a result
readback obligation, while an affirmative mutation clause still does, and that
an explicit 70-item scope is not narrowed by five attachments. The eight Hook
definitions remain byte-identical to 0.6.3. Current source acceptance includes
schema-5 migration, local/data-URL image
hashing and dimensions, transcript-tail supplementation, no-byte persistence,
Chinese/English positive and negative cases, adversarial wording, wrong-surface
and cross-item rejection, and the anonymized 48-of-70 subset incident replay.
Scoped native macOS and Windows acceptance passed for the frozen 0.7.3 source,
installation, archive, strict no-op, and installed lifecycle boundaries. The
release is published from the exact validated `main` commit as `v0.7.3`; CI
and HOL verify the source commit and tag separately and do not substitute for
either native run.

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
