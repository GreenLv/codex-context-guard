# Compatibility and Verification Status

Compatibility statements are evidence-bounded. Passing unit tests on one
platform does not prove a fresh installed runtime on another platform.

## Baselines

- Current source candidate: `0.11.1` (unreleased maintenance patch)
- Current published Context Guard release: `0.11.0`
- Private state schema: `9` (schema 7 and 8 read-only compatibility)
- Proof protocol: `1.0.0`
- Stop protocol: `2.1.0`
- Execution protocol: `2.0.0`
- Diagnostic classifier: `2.4.0`
- Python: `3.10+`
- Codex CLI tested minimum: `0.146.0`
- Runtime dependencies: Python standard library only

The Codex minimum is a tested lower bound. Hook schemas and plugin installation
behavior may change in future Codex releases and must be revalidated.

## 0.11.1 candidate status

Version 0.11.1 includes managed marketplace migration. It recognizes the
exact historical fixed-name staging directory when its manifest still binds to
this repository, then re-registers the current commit-addressed staging copy.
It also restores the release authorization bridge: `action-ticket/v1` accepts
the current `release-readiness/v3` producer output and the explicit legacy `v2`
value, while every unknown readiness schema fails closed.
The public state schema, Hook event set, protocol identifiers, diagnostic
classifier version, and Python baseline are unchanged. Source and native
candidate validation are still required before release.

## 0.11.0 release status

Version 0.11.0 adds the synchronous `PreToolUse` event, exact
`action-ticket/v1` enforcement for A-tier publication identity mutations,
root-user target matching for B-tier remote mutations, and append-only
`work-unit/v1` state. Stop 2.1.0 validates declared waits and deferrals against
observed ownership, authorization, and dependency facts. Quoted, attributed,
code, and reply-annotation text is excluded before supersession attribution.

Runtime baseline `ea73bed7a387295e1f6475e743e623298413e710`
passed the complete source suite, isolated installation/no-op, 68-file parity,
the nine-Hook self-test, lifecycle smoke, action-ticket cases, and fresh-task
Hook acceptance independently on macOS and Windows. The Windows result has
explicitly authorized remote-reported provenance rather than a locally signed
machine annex. Hook enforcement is a strong guardrail, not a complete security
boundary: platform approval remains in force and specialized tools that do not
participate in Codex Hooks remain an explicit coverage gap.

## 0.10.0 release status

Version 0.10.0 advances private state to schema 8 and the diagnostic classifier to 2.4.0. It derives the required operation, subject, and requested surface from non-negated clauses; evidence for a different operation or adapter manifest cannot close the item. Schema 7 remains a read-only compatible input and upgrades deterministically.

Implementation baseline `e4fccf690bcbc2be79d0b8d42a1a269f87072120` and documentation candidate `8178569634190df37ed0c342f8604e63e283082f` share the same 19-file runtime tree, with SHA-256 `aee9a33d40855ddf5efdbd1fec7f327945a273f15eb5f64ff53fefed2a40f6b7`. Candidate `8178569` passed the complete local source matrix and main CI run `33592448790` across 12 Ubuntu, macOS, and Windows Python jobs. macOS passed isolated and managed installation, strict no-op, four-way byte parity, installed lifecycle smoke, and a fresh trusted-Hook task. Windows independently passed source, isolated install/no-op/parity, self-test, and lifecycle smoke for the implementation baseline. Context Guard has no separate package artifact; the source tag is its release identity. DSH Completion Guard has its own artifact and native-platform evidence, which does not substitute for a Codex gate.

## 0.9.5 release status

Version 0.9.5 keeps schema 7, Stop protocol 2.0.0, Proof and Execution protocol
1.0.0, classifier 2.3.2, Python 3.10+, and the eight-Hook wire. It automatically
derives ordinary non-visual proof records from successful reads when a
checkpoint is staged, narrows UI-wording classification, and binds task, file,
and Windows-path evidence to the exact item that was read. Images, UI results,
and scopes that cannot be checked exactly still require explicit proof.

Native macOS and Windows independently pass source, installation, strict
repeat/no-op, product-parity, installed lifecycle, and fresh trusted-Hook
gates for the 0.9.5 product bytes. Documentation-only release commit
`e0aed2d7bdbd88643ae2559dc8cd655aa369e049` passes the 12-job main and tag CI
matrices; the same commit passes the main-branch HOL scan. Annotated tag
`v0.9.5` resolves to that commit, and its bilingual, non-prerelease GitHub
Release is the latest published release. Downstream consumer updates remain a
separate adoption surface.

## 0.9.4 release status

Version 0.9.4 carries forward the Stop protocol introduced by the consumed,
unpublished 0.9.0 through 0.9.3 candidates and fixes the Hook payload
transport. Under Stop protocol 2.0.0, an authenticated full-coverage
checkpoint is the sole authority for completion. Classifier 2.3.2 remains
diagnostic-only; privacy, integrity, invalid control, and explicit
user-persistence failures remain hard gates. Schema 7, Proof protocol 1.0.0,
Execution protocol 1.0.0, Python 3.10+, and the eight-Hook wire are unchanged.

The `Stop` and `UserPromptSubmit` hook entrypoint now reads raw stdin bytes and
decodes them as UTF-8 explicitly instead of accepting the host locale codec.
On Windows hosts whose ANSI code page is a legacy multibyte code page, the
previous behavior corrupted every non-ASCII payload byte before journaling:
requirements and completion wording were stored mojibake-prefixed, the
classifier could not observe completion-claim text, and payload bytes that were
invalid in that codec crashed the hook process instead of producing a visible
result. The corrected transport journals payload text byte-exactly and rejects
bytes that are not valid UTF-8 with a visible one-line message while exiting
cleanly, matching the established invalid-JSON contract. Subprocess
regressions cover byte-exact Chinese journaling, the full UTF-8 Stop decision
contract, and invalid-byte rejection. Hosts that already deliver UTF-8 pipes
are unaffected except for the added invalid-byte visibility.

The public incident manifest contains eight reviewed fixtures across eight
root-cause families. The immutable 0.8.12 runtime reproduces two target false
continuations, while the current 0.9 source produces zero. Source, installed,
native macOS, and native Windows evidence is recorded independently in the
[development plan](DEVELOPMENT_PLAN_0.9.md) and acceptance record. PR,
exact-main CI/HOL, annotated-tag CI, the bilingual GitHub Release, and public
readback pass as separate gates.

The private incident-corpus tool uses exact `0700`/`0600` modes on POSIX and a
protected, dual-read-back-verified DACL on Windows. It calls
`SetNamedSecurityInfoW` with only DACL and protected-DACL flags, null owner,
group, and SACL pointers, and access entries for the current user, `SYSTEM`, and
the built-in Administrators group. Verification uses both the supported
`GetAccessRules` API and `RawSecurityDescriptor`; each path requires exactly
those three unique Allow FullControl ACEs, the correct directory/file
inheritance flags, and protected-DACL state. A missing PowerShell host or a DACL
that cannot be written and verified is a fail-closed corpus-tool failure; it does
not weaken the independent public-fixture benchmark or Hook runtime privacy
gates.

The 0.9.0 candidate passed native macOS acceptance before the POSIX-mode gap was
found during native Windows source testing. The 0.9.1 candidate introduced a
protected ACL, passed macOS acceptance, and then failed closed on native Windows
because `Set-Acl` requested `SeSecurityPrivilege` from a standard user token.
Both candidates were installed and consumed, so their caches are immutable.
Version 0.9.2 advanced the package identity and wrote only the DACL rather than
repairing either candidate in place. Native Windows then confirmed that the
write succeeded and both supported readback paths contained the exact three
ACEs, while the PowerShell `.Access` adapter did not reliably enumerate the
collection. Version 0.9.3 changed the verification path and package identity
without rewriting any consumed cache, passed the Windows source gates, and was
installed; its first native fresh-Hook run then exposed the stdin transport
defect corrected by 0.9.4, which advances the package identity without
rewriting any consumed cache.

Exact 0.9.1 candidate `02e7f57` passes the complete macOS source suite with 225
tests and five capability-aware skips, isolated and default-home installation,
strict second no-op, source/staging/live/archive parity, installed self-test and
lifecycle smoke, restoration of archived 0.8.12 and 0.9.0 live trees, and a
fresh trusted Stop replay with zero continuations. Native Windows must rerun
the ACL-focused and complete source suites before installation; this macOS
evidence does not substitute for that gate. Native Windows 0.9.1 passes three
of five focused incident-corpus tests and then stops at the `Set-Acl`
`SeSecurityPrivilege` failure; benchmark report absence is downstream of that
failure. The consumed 0.9.2 DACL-only correction exposed the readback-
enumeration defect on native Windows.
On macOS, exact 0.9.2 source, isolated/default installation, strict no-op,
four-way parity, installed smoke/recovery, and fresh trusted-Hook evidence pass;
historical 0.8.12, 0.9.0, and 0.9.1 live trees were restored from immutable
archives after host cleanup without changing their content digests. This does
not substitute for native Windows execution of the corrected verification
contract. Native Windows on exact `56cb70a` passes the complete source gate
(233 tests with six capability-aware skips, ten focused incident-corpus tests
including a pinned Windows PowerShell 5.1 ACL regression), the benchmark with
8/8 authority outcomes and the unchanged fixture manifest hash, isolated and
default-home installation with strict second no-op and staging/live/archive
parity, installed self-test and lifecycle smoke, and a fresh no-bypass
non-interactive task whose persisted state records the full Stop decision
contract with byte-exact Chinese journaling. Native macOS independently passes
the repository and privacy gates, ten focused incident tests with four
Windows-only skips, the benchmark at 8/8 with zero false continuations and
diagnostic accuracy 1.0, 233 tests with nine capability-aware skips, the
eight-Hook self-test, Ruff, external-cache compilation, and diff checks. Fresh
isolated and default homes pass installation, strict no-op and read-only
audits, 46-file source/staging/live/archive parity, installed self-test, and
lifecycle smoke; all 16 indexed default-home live/archive pairs remain equal.
Fresh no-bypass tasks exercise UserPromptSubmit, PostToolUse, Stop, and
SessionEnd from installed 0.9.4 with byte-exact Chinese journaling, zero Unicode
repairs, the authoritative `protocol_default/allow_neutral` outcome, one
preserved pending requirement, and zero continuations. PR, exact-main CI/HOL,
annotated-tag CI, the bilingual Release, and public readback pass independently.

## 0.8.12 release status

Version 0.8.12 advances only the completion classifier and package identity.
Classifier 2.3.2 treats a completion phrase inside a bounded quotation followed
by a Chinese category label such as `类声明` or `这种表述` as meta-discussion,
while standalone quoted assertions and explicit first-person confirmations
remain whole-task completion claims. Schema 7, the Proof, Stop, and Execution
protocols, Python baseline, and eight-Hook wire are unchanged.

Focused source regressions replay the reported Stop decision and retain direct
completion controls. Repository and privacy validation, 219 tests with five
capability-aware skips, the eight-Hook self-test, Ruff, external-cache
compilation, and diff checks pass on macOS. Exact candidate
`c66ac824f0d9d2015f1725417a2e50f5a96f31da` passes managed installation,
strict repeat/no-op readback, installed self-test, lifecycle smoke, and fresh
trusted eight-Hook tasks on native macOS and Windows. Both native tasks persist
clean schema-7 state and `SessionEnd` recovery after normal exit. CI, HOL, the
annotated tag, GitHub Release, public readback, and downstream consumer pinning
remain independently verified evidence surfaces.

## 0.8.11 release status

Version 0.8.11 folds in the consumed 0.8.9 and 0.8.10 candidates (schema 7,
classifier 2.3.1, Proof/Stop/Execution protocols) and changes only Hook
command resolution plus installer diagnosis. The consumed 0.8.10 candidate
introduced the fallback; 0.8.11 tightens its version gate to the documented
strict-semver contract: both command forms accept only a lone `X.Y.Z`-shaped
directory (exactly three dot-separated numeric components, no leading zeros)
as a surviving candidate, and a lone `0.0.0` tree is still a valid first
candidate on both platforms.

An observed macOS Codex CLI 0.149.0 default home pruned every historical
versioned live cache when a fresh task started on 2026-08-26, keeping only the
installed 0.8.9 tree. The hash-indexed archive stayed intact, but an open task
that still referenced its pruned `$PLUGIN_ROOT` path lost later Hook
invocations until a safe-installer apply restored the exact bytes. Managed-apply
preservation therefore does not extend to host task-startup cleanup. Native
Windows acceptance on Windows 10.0.26200.9168 did not reproduce the pruning
during its fresh task, so cleanup remains an observed macOS host behavior, not
a universal cross-platform claim.

Both Hook command forms now prefer the pinned plugin root and otherwise resolve
the newest surviving strictly semver-named (exactly three dot-separated numeric
components, no leading zeros), non-symlink Context Guard tree
under the managed marketplace cache root (`CODEX_HOME` when set, otherwise
`~/.codex`), failing closed with an actionable reinstall hint when nothing
survives. Windows hosts execute `commandWindows` through a shell with
PowerShell semantics that expands `$env:` references, as the accepted 0.8.8
`-File` form proved; the payload is therefore the readable PowerShell resolver
itself, with no nested invocation or transport quoting that an outer layer
could strip. The
fallback executes only trees materialized by the host from the
sanitized marketplace source; it may run a newer runtime than the one a
rescued task originally trusted, it does not verify per-file hashes at spawn
time, and it never mutates consumed caches. The hash-indexed archive remains
the only authority for restoring exact historical trees. Read-only installer
runs now name host startup pruning and the `--apply` restore action directly.

Exact candidate `d7c9b0b5769c110c743f2a20a487ac40078d7713` has independent
native acceptance on macOS and Windows with Codex CLI 0.149.0 and Python 3.12.
Both platforms passed default-home managed installation, strict second no-op,
read-only audit, 15-product-file source/staging/live/archive parity, installed
eight-Hook self-test, lifecycle smoke, and fresh interactive trust without a
bypass. The Windows run additionally executed the native PowerShell resolver
gate and preserved its historical live-cache set across fresh task startup;
the macOS run observed pruning and verified manager restoration from the
trusted archive. CI, main/tag state, GitHub Release publication, and downstream
consumer pins remain separate evidence surfaces.

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
