# Local Release Acceptance

This document records local and remote acceptance evidence for standalone
Context Guard. The current source and published release is `0.11.0`. Accepted releases include `0.11.0`, `0.10.0`, `0.9.5`, `0.9.4`, `0.8.12`, `0.8.8`, `0.8.7`, `0.8.6`, `0.8.5`, `0.8.4`, `0.8.3`, `0.7.7`, `0.7.6`, `0.7.3`,
`0.5.1`, and historical `0.5.0`/`0.4.9` evidence remains below.

## 0.11.0 release-candidate acceptance (2026-09-03)

Implementation candidate `ea73bed7a387295e1f6475e743e623298413e710`
is the 0.11.0 runtime subject. It adds schema 9, Execution protocol
2.0.0, Stop protocol 2.1.0, `work-unit/v1`, and the ninth Hook event,
`PreToolUse`. Its source/install tree contains 68 files. The macOS and Windows
results below are independent native evidence for that exact commit.

Normal-user-home installation is intentionally outside this release scope. CI,
tag, GitHub Release, and public readback are separate publication surfaces;
this pre-publication record neither authorizes nor infers them from isolated
native installation and testing.

| Release-candidate gate | Evidence | Status |
| --- | --- | --- |
| Complete source suite | 412 tests with 9 capability-aware platform skips on macOS/Python 3.12.2; 412 tests with 6 explicit platform skips on Windows/Python 3.12.10 | passed independently |
| Repository and public-tree contracts | `validate_public_repo.py`, `audit_public_tree.py`, JSON schema parsing, external-cache compilation, and `git diff --check` | passed |
| Hook bundle and lint | source self-test reports exactly 9 Hook events; Ruff 0.16.1 passes with cache disabled | passed |
| Public incident benchmark | Stop 2.1.0 / Execution 2.0.0 passes 8/8 reviewed fixtures with zero false continuations and diagnostic accuracy 1.0 | passed |
| Public taxonomy coverage | 8 of 12 taxonomy roots have reviewed public fixtures; the four new roots remain intentionally private-only pending human review | bounded, not a failure |
| Native macOS | Isolated managed install, strict second apply/no-op, 68/68 source/live byte parity, installed self-test and lifecycle smoke, and a fresh task; an unticketed `git tag v9.9.8` was denied by real `PreToolUse` and independent readback proved the tag absent | passed |
| Native Windows | R2 ZIP SHA-256 `fa00295b7cb0b8630673b820cec609958984cc810c3d0c2a0051151ed8e40480`; isolated install/no-op, 68/68 relative-path and per-file SHA-256 parity, 9-Hook self-test, action-ticket lifecycle, and a fresh task; an unticketed `git tag v1.2.3` was denied and independent readback reported zero matching tags | passed, remote-reported provenance |
| Windows wrapper regression | `/bin/zsh -lc 'git tag …'`, PowerShell-wrapped `gh release delete …`, and a quoted `pwsh.exe`-wrapped `npm publish` were all classified A-tier and denied without a ticket | passed, remote-reported provenance |

The Windows result is explicitly recorded with remote-reported provenance. The
root user authorized that provenance after disclosure that the native task did
not return a locally signed machine annex. Its private, redacted evidence hash
is retained outside Git. The normal Windows checkout remained clean at its
original base commit, and no normal installation, commit, push, tag, GitHub
Release, registry mutation, or publication occurred.

## 0.10.0 release acceptance (2026-09-03)

Commit `e4fccf690bcbc2be79d0b8d42a1a269f87072120` is the 0.10.0 implementation baseline. Candidate `8178569634190df37ed0c342f8604e63e283082f` changes only non-packaged documentation after that baseline, so both have the same 19-file runtime tree and SHA-256 `aee9a33d40855ddf5efdbd1fec7f327945a273f15eb5f64ff53fefed2a40f6b7`. The annotated `v0.10.0` tag identifies the exact release commit that contains this record.

| Gate | Current evidence | Status |
| --- | --- | --- |
| Runtime identity | 19 product files; runtime-tree SHA-256 `aee9a33d40855ddf5efdbd1fec7f327945a273f15eb5f64ff53fefed2a40f6b7` | passed |
| Source and CI | Candidate `8178569` passed 372 tests with 9 capability skips, repository and public-tree validation, Ruff, compilation, eight-Hook self-test, and main CI run `33592448790` with 12 independent jobs | passed |
| Native macOS | Isolated and managed installation, strict second apply/no-op, read-only audit, source/staging/live/archive parity, installed self-test and lifecycle smoke, plus a fresh trusted-Hook task | passed |
| Native Windows | Source, isolated installation, strict second apply/no-op, read-only audit, installed-file parity, eight-Hook self-test, and lifecycle smoke at implementation baseline `e4fccf6` | passed |
| Separate package artifact | Not applicable: Context Guard installs from the source repository and tag; no standalone package is published | not applicable |
| Tag and GitHub Release | Annotated `v0.10.0` and a bilingual non-prerelease GitHub Release identify the release commit | passed after public readback |
| Downstream adoption | Consumer updates remain separate from the standalone release | pending |

The macOS and Windows results cover the same runtime-tree bytes but remain independent platform evidence. The release-document commit requires its own documentation checks and exact main CI before tagging; those checks do not need to repeat native installation because no runtime byte changed. The DSH Completion Guard artifact and its platform results belong to a different repository and do not close any Codex gate.

## 0.9.5 release acceptance (2026-09-01)

The 0.9.5 product candidate is exact commit
`745b7fb5bf0127cc38e649ec56f3f1f7b5fa8fa5`. Its product tree contains 17
files under the plugin-owned roots. Documentation-only release successors do
not change those runtime/install bytes, but they still require their own
repository checks and exact-main automation before tagging.

- Native macOS passes `validate_public_repo`, `audit_public_tree`, 343 tests
  with 9 capability skips, the eight-Hook self-test, Ruff, external-cache
  compilation, and `git diff --check`. An isolated home and the daily home both
  pass managed 0.9.5 installation, strict second apply/no-op, read-only audit,
  installed self-test, lifecycle smoke, and 17-file source/cache parity. The
  daily upgrade preserves the immutable 0.9.4 cache and archive.
- A fresh macOS Codex CLI 0.150.1 task, without Hook-trust bypass, loads the
  installed 0.9.5 Skill and reads the requested source file. Persisted schema-7
  state records integrity `ok`, a complete turn-bound checkpoint, zero open
  items, zero continuations, and a normal `SessionEnd`.
- Native Windows independently accepts the same exact 0.9.5 commit through its
  source, isolated install/no-op/parity, and fresh trusted-Hook lifecycle. Its
  standard 24-gate annex validates as `native_source/passed`; this isolated
  acceptance does not claim a Windows daily-home upgrade.
- Exact product commit `745b7fb5bf0127cc38e649ec56f3f1f7b5fa8fa5`
  passes CI run `33461874654` and HOL Plugin Scanner run `33461874644`.
  Documentation-only release commit
  `e0aed2d7bdbd88643ae2559dc8cd655aa369e049` passes main CI run
  `33485553819`, HOL run `33485554097`, and tag CI run `33486033348`.
  Annotated tag `v0.9.5` peels to that exact commit. The bilingual,
  non-draft, non-prerelease GitHub Release is the latest release and was read
  back through the public repository API. Downstream pinning and a Windows
  daily-home upgrade remain separate consumer gates.

## Post-release semantic conformance gate acceptance (Windows, 2026-08-30)

Native Windows 11 source acceptance used a fresh isolated checkout of exact
commit `b59fcfe1aaf8ead3f0438bc67dc7f725c869a473` with Python 3.12.10,
Windows PowerShell 5.1, and Ruff 0.16.1. Repository validation, the tracked-tree
privacy audit, 313 tests with six capability-aware skips, the eight-Hook
self-test, Ruff, compilation, `git diff --check`, the native PowerShell launcher,
and both reference digest encoder gates passed. The digest fixture contained 29
byte-identical golden vectors, and its raw `cases.json` SHA-256 matched the DSH
mirror under the host's effective `core.autocrlf=true` setting.

This result accepts the post-release portable digest and conformance assets on
native Windows. It does not claim that the planned stop-policy, boundary,
semantic-action, or Goal integration is implemented, and it is not a new
installed-plugin, tag, package, or release acceptance result.

## 0.9.4 release acceptance (2026-08-28)

The release advances the plugin identity to 0.9.4 and retains Stop protocol
2.0.0, schema 7, classifier 2.3.2, Proof protocol 1.0.0,
Execution protocol 1.0.0, Python 3.10+, and the exact eight-Hook wire.
The consumed, unpublished 0.9.0, 0.9.1, 0.9.2, and 0.9.3 candidates remain
immutable.

The consumed 0.9.3 candidate passed the Windows source gates and installation,
and its first native Windows fresh-Hook run exposed two separate facts that
0.9.4 addresses or records. First, the bare meta-discussion prompt did not
activate the guard, so no Stop decision fields could exist for that run;
activation is by design and the acceptance procedure now triggers it
explicitly. Second, an isolated byte-level replay proved that the runtime
decoded hook stdin with the host ANSI code page: a clean UTF-8 payload was
persisted mojibake-prefixed, which explains why journaling and the classifier
could not observe completion wording on this host. Version 0.9.4 fixes the
transport and adds subprocess regressions; it does not change any protocol.

Native Windows source acceptance for exact 0.9.4 implementation `56cb70a`
passes repository validation, the tracked-tree privacy audit, 233 tests with
six capability-aware skips, the eight-Hook self-test, Ruff 0.16.4,
external-cache compilation, and `git diff --check` with Python 3.12.10. The
focused incident-corpus suite reports ten passing tests: the nine 0.9.3 ACL
tests plus a new regression that drives the ACL script through Windows
PowerShell 5.1. This host has no PowerShell 7 install, so the 0.9.3 focused
suite failed closed at `FileSystemAclExtensions`, a .NET Core class absent
from the .NET Framework runtime that Windows PowerShell 5.1 embeds; the 0.9.4
script branches on the PowerShell major version and passes natively under
5.1, which is a stronger boundary than the previous pwsh-dependent run. The
new hook-transport regressions cover byte-exact Chinese journaling, the full
UTF-8 Stop decision contract, and visible invalid-byte rejection, and each
fails on the 0.9.3 runtime. The reviewed public benchmark passes 8/8 authority
outcomes with zero false continuations and diagnostic accuracy 1.0; the
`fixture_manifest_sha256` remains
`ec6dc9fdc4b63b8f4e18b4f4ca2335d86665e6e39be4444e829262811569af54` while the
benchmark report files hash differently from 0.9.3 because the runtime bytes
changed, and repeated runs are deterministic.

A fresh isolated home passes installation, strict second no-op, 46-file
source/staging/live/archive parity, installed eight-Hook self-test, and the
lifecycle smoke including compaction recovery. The default home run recorded
pre-install digests for every archived version, applied the safe installer,
repaired all eight historical live trees strictly from their trusted archives
after the host removed them again, and passed a strict second no-op. Every
archive matched its pre-install digest, every restored live tree matched its
archive exactly, and the consumed 0.9.3 live/archive pair stayed untouched at
46 files. The 0.9.4 staging/live/archive trees share one 46-file digest, and
the installed self-test and smoke pass against the live tree.

A fresh no-bypass native Windows 0.9.4 task then ran non-interactively on
Codex CLI 0.150.1 with the bounded Chinese meta-discussion sentence as its
reply contract, prefixed with the explicit `$context-guard` activation word.
The assistant echoed the sentence once with the curly quotes intact, and the
UserPromptSubmit, PostToolUse, and Stop hooks fired from the installed 0.9.4
tree. Persisted schema-7 state recorded integrity ok, activation through the
explicit control, Stop protocol 2.0.0, classifier 2.3.2,
`observed_outcome=gate_completion_claim`, authoritative
`protocol_default/allow_neutral`, one pending requirement preserved, zero
continuations, a completed SessionEnd, and a byte-exact prompt journal with
zero unicode repairs. Configuration-level trust shows all eight product hook
events registered and trusted for `context-guard@codex-context-guard`; the
equivalent `/hooks` UI display was verified on the same wire in the previous
round. After the fresh task, every archive digest still matched its pre-install
value and every live tree still matched its archive.

Native macOS acceptance then used clean documentation successor `fcfbfc7` for
frozen implementation `56cb70a` with macOS 26.6.2, Python 3.12.2, Ruff 0.16.1,
and Codex CLI 0.150.1 under a standard user account. Repository validation,
the tracked-tree privacy audit, ten focused incident-corpus tests with four
capability-aware Windows skips, the reviewed benchmark, 233 tests with nine
capability-aware skips, the eight-Hook self-test, Ruff, external-cache
compilation, and `git diff --check` passed. The benchmark retained the reviewed
manifest hash above, passed all eight authority outcomes, produced zero false
continuations, and reported diagnostic accuracy 1.0.

A fresh isolated macOS home passed managed installation, strict second no-op,
read-only audit, 46-file source/staging/live/archive parity, installed
eight-Hook self-test, lifecycle smoke, and forbidden-residue checks. The
default home then installed 0.9.4 through the same manager, restored 15
historical live trees only from trusted archives, and passed a strict second
no-op, read-only audit, installed self-test, lifecycle smoke, and parity for
all 16 indexed live/archive versions. The 0.9.4 staging/live/archive trees
remained identical at 46 files.

Two fresh no-bypass macOS tasks exercised the installed 0.9.4 tree. The first
proved exact fixed-response, byte-exact UTF-8 journaling, Stop, and normal
SessionEnd. The second added a read-only tool call and therefore fired
UserPromptSubmit, PostToolUse, Stop, and SessionEnd. Persisted schema-7 state
reported integrity ok, explicit activation, classifier 2.3.2, Stop protocol
2.0.0, `observed_outcome=gate_completion_claim`, authoritative
`protocol_default/allow_neutral`, one preserved pending requirement, zero
continuations, and zero Unicode repairs. A final managed apply, repeat apply,
and read-only audit were strict no-ops; all 16 live/archive pairs and the
current three-way parity remained intact.

The reviewed public incident manifest SHA-256 is
`ec6dc9fdc4b63b8f4e18b4f4ca2335d86665e6e39be4444e829262811569af54`.
It contains eight fixtures across completion semantics, action handoff, privacy
metadata, receipt adaptation, proof/scope/visual, compaction/recovery,
Hook/cache lifecycle, and cross-platform compatibility. The immutable 0.8.12
runtime passes its historical expectations and reproduces two target false
continuations; the 0.9 source passes all eight target authority outcomes with
zero false continuations and diagnostic accuracy reported separately as 1.0.

A fixed-seed unit gate exercises 10,000 staged-control transitions across
English, Chinese, quotation, code, hypothetical, negated, first-person, and
attributed speech. Repository validation, the tracked-tree privacy audit, 226
tests with five capability-aware skips, the eight-Hook self-test, Ruff,
external-cache compilation, and `git diff --check` pass for the 0.9.2 source on
macOS.

Consumed 0.9.0 candidate `429825f` passes a fresh isolated install, strict second
install no-op, read-only diagnosis, full source/staging/live/archive parity,
installed self-test, lifecycle smoke, and a focused installed Stop 1.1 state
migration. The default macOS installation preserved and verified the immutable
0.8.12 live/archive pair, then passed the same 0.9 no-op, parity, and smoke
chain on Codex CLI 0.150.1. These installed and native results do not substitute
for exact 0.9.2 installed and native reruns after the DACL-only correction.

Native Windows first checked branch head `111cb7f` with Python 3.12.10,
PowerShell 7.6.4, and Codex CLI 0.150.1. The public incident benchmark passed
all eight fixtures with zero false continuations, diagnostic accuracy 1.0, and
the reviewed manifest hash above. Repository and privacy validation passed.
The complete source suite then stopped at two real failures: report-file tests
required POSIX `0600` mode bits and private-root tests required POSIX `0700`
mode bits. Native reruns reproduced both outside the sandbox. Installation and
fresh-Hook gates were not started, and no 0.8.12 cache was touched.

Exact 0.9.1 correction `02e7f57` replaces that false Windows contract with a
protected ACL that grants full control only to the current user, `SYSTEM`, and
the built-in Administrators group, removes inheritance, and reads the ACL back.
Failure to apply or verify it is fail closed. On macOS, this exact commit passes
repository and privacy validation, 225 tests with five capability-aware skips,
the eight-Hook self-test, Ruff, external-cache compilation, and diff checks. A
fresh isolated home passes installation, strict second no-op,
source/staging/live/archive parity, installed self-test, lifecycle smoke, and
Stop 1.1 recovery. The default home passes the same install/no-op/parity/smoke
chain; its repair restored archived 0.8.12 and 0.9.0 live trees without changing
their trusted archive parity.

A fresh no-bypass native macOS 0.9.1 task displayed exactly eight installed and
active Context Guard Hooks; the inspected PostToolUse definition reported
`Plugin - context-guard@codex-context-guard` and `Trust: Trusted`. A separate
fresh real-model replay returned the bounded Chinese meta-discussion sentence
once. Its persisted schema-7 state recorded Stop protocol 2.0.0,
`observed_outcome=gate_completion_claim`, authoritative
`protocol_default/allow_neutral`, one pending item, zero continuations, and a
completed `SessionEnd`.

Native Windows then fast-forwarded cleanly to 0.9.1 documentation head
`360fad2`, confirmed ACL implementation commit `02e7f57` as an ancestor, and
verified plugin 0.9.1 with Stop protocol 2.0.0. The focused incident-corpus
suite reported three passes, one failure, and one error before downstream
benchmark-report creation. The first root failure occurred at `Set-Acl` under
a standard user token because that path requested `SeSecurityPrivilege`.
Fail-closed behavior held: no POSIX fallback, skip, install, cache mutation, or
fresh-Hook run occurred.

The 0.9.2 source candidate removes `Set-Acl` and owner mutation. Its native call
sets only `DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION`,
passes null owner, group, and SACL pointers, and independently reads back only
access-control sections. This matches the Windows requirement that an owner or
caller with `WRITE_DAC` may set a DACL without the `SeSecurityPrivilege` needed
for SACL changes. Native Windows must rerun all six focused tests before the
complete source and installation gates resume.

Native Windows diagnosis at clean branch head `2314e2d` confirmed the 0.9.2
write path rather than an empty DACL: the constructed `RawAcl` contained three
Allow FullControl ACEs, its binary header reported three ACEs with matching ACL
size and binary length, the native DACL pointer was non-null, and
`SetNamedSecurityInfoW` returned success. Both `GetAccessRules` and an
independently parsed `RawSecurityDescriptor` read back exactly the three required
ACEs with protected-DACL state and the correct directory/file inheritance flags.
The PowerShell `.Access` adapter did not reliably enumerate that collection.
The consumed 0.9.3 candidate therefore retained the native write and replaced
only the strict verification path. Nine focused Windows tests passed under a
non-administrator standard user token with `SeSecurityPrivilege` unavailable,
including real directory/file writes, dual readback, missing/extra/Deny
rejection, and readback failure containment.

The same consumed 0.9.3 Windows worktree passed the reviewed eight-fixture
benchmark with 8/8 authority outcomes, zero false continuations, diagnostic
accuracy 1.0, and manifest SHA-256
`ec6dc9fdc4b63b8f4e18b4f4ca2335d86665e6e39be4444e829262811569af54`.
Repository validation, tracked-tree privacy audit, 229 tests with six
capability-aware skips, the eight-Hook self-test, Ruff 0.16.1, external-cache
compilation, and `git diff --check` passed with Python 3.12.10. The three
PowerShell resolver tests require a process-scoped execution-policy bypass on
this host; all three passed under that bounded test environment. No repository
cache or generated bytecode remained in the worktree.

Exact 0.9.2 implementation `37612bf` and its documentation successor pass the
complete 226-test macOS source gate with five capability-aware skips. A fresh
isolated home and the default home both pass installation, strict second no-op,
16-file source/staging/live/archive parity, installed eight-Hook self-test,
lifecycle smoke, and focused installed Stop 1.1 recovery. Content digests for
consumed 0.8.12, 0.9.0, and 0.9.1 live/archive trees are identical before and
after the default-home run.

A fresh no-bypass native macOS 0.9.2 task displayed all eight product events as
installed and active. Its PostToolUse detail identified
`context-guard@codex-context-guard` as the source and displayed trusted status.
The bounded Chinese meta-discussion reply appeared once and produced no
continuation. Persisted schema-7 state recorded Stop protocol 2.0.0,
`observed_outcome=gate_completion_claim`, authoritative
`protocol_default/allow_neutral`, one pending requirement, zero continuations,
and SessionEnd. Starting the fresh task removed historical live-cache trees;
the safe installer restored all of them only from trusted archives, preserved
the three consumed-version content digests above, and then passed another
strict no-op.

Native macOS evidence above does not substitute for native Windows, and the
independent Windows evidence does not substitute for macOS. PR #17 and all 12
OS/Python jobs plus HOL pass on acceptance successor `81c2df8`; the same exact
commit then passes all 12 jobs and HOL after an ordinary fast-forward to main.
Annotated tag `v0.9.4` points to release commit `7b829eb`; all 12 tag CI jobs
pass. The non-draft, non-prerelease bilingual GitHub Release is the latest
release, its English and Chinese sections link their matching changelogs, and
unauthenticated public API, release-page, latest-redirect, and raw-changelog
readback pass. The completed boundary is recorded in
[the 0.9 development plan](DEVELOPMENT_PLAN_0.9.md) and the
[GitHub Release](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.9.4).

## 0.8.12 release acceptance (2026-08-27)

The release source advances the plugin identity to 0.8.12 and the
completion classifier to 2.3.2. A focused Stop regression replays the reported
reply in which `“任务已完成”类声明` is a quoted category label, not the
assistant's own completion assertion. The corrected path yields the staged
deferred boundary with zero continuations, while standalone quoted completion,
first-person confirmation, and quantified whole-task completion remain direct
claims.

The candidate passes repository validation, the tracked-tree privacy audit,
219 tests with five capability-aware skips, the eight-Hook self-test on Python
3.12.2, Ruff 0.16.1 without a repository cache, external-cache compilation,
and `git diff --check`. A separate focused run passed 16 classifier, Stop, and
public-contract tests plus repository validation.

Exact candidate `c66ac824f0d9d2015f1725417a2e50f5a96f31da` was then
installed through the managed entry point on the macOS and Windows default
Codex homes. Both platforms passed the strict repeated apply, read-only
readback, installed eight-Hook self-test, and lifecycle smoke. Windows also
passed the PowerShell launcher self-test under Python 3.14.6 after the direct
Python 3.12.10 self-test and full installed smoke.

Fresh interactive tasks on both native platforms displayed exactly eight
installed and active Context Guard Hooks. `SessionStart` was enabled from
`context-guard@codex-context-guard` with `Trust: Trusted`; no trust bypass was
used. `UserPromptSubmit`, `PostToolUse`, and `Stop` exercised the private
completion control, the requested fixed reply returned, and status readback
reported `integrity=ok`, classifier 2.3.2, Stop protocol 1.1.0, Proof protocol
1.0.0, one closed requirement, and no open items. Normal exit persisted
`SessionEnd` and both recovery files on macOS and Windows. A malformed Windows
private-control attempt was rejected fail-closed before a corrected invocation
succeeded; the unrelated `chrome-devtools` and Zotero MCP startup warnings did
not affect the Hook lifecycle.

PR #16 at candidate documentation head `c66ac82` passes the 12-job
`ubuntu-latest`, `macos-latest`, and `windows-latest` Python 3.10-3.13 matrix,
the HOL Plugin Scanner, and plugin scanner. The release-status successor changes
only public documentation and contract tests; main CI/HOL, tag CI, the annotated
tag, GitHub Release, public release readback, and downstream consumer pin remain
separate publication evidence.

## 0.8.11 release acceptance (2026-08-26–2026-08-27)

Consumed 0.8.10 recap (recorded, not a release): that candidate introduced the
Hook command fallback after an observed macOS Codex CLI 0.149.0 host pruned
historical versioned live caches at fresh-task startup. On the default home a
managed upgrade archived 0.8.10 and repaired every host-pruned tree (0.6.1
through 0.8.9); a real fresh `codex exec` task fired the installed 0.8.10 Hook;
the host then genuinely pruned all historical live versions again; consumed
0.8.9 bytes failed with exit 127 while installed 0.8.10 bytes returned exit 0
through the fallback and persisted schema-7 state; and a later apply restored
every version. Review then found the 0.8.10 fallback version gate was looser
than the documented strict-semver contract, so 0.8.10 stays a consumed
intermediate and 0.8.11 narrows the gate.

The 0.8.11 release source passes repository validation, the tracked-tree
privacy audit, 218 unittests with five capability-aware skips, the eight-Hook
self-test on Python 3.12.2, Ruff 0.16.1, external-cache compilation, the
commit-identity audit of the unchanged public baseline, and `git diff --check`.
Adversarial resolver regressions now cover, on POSIX and (via Windows CI) the
PowerShell form: pinned-root preference, newest-survivor fallback, decoy and
symlink rejection, fail-closed reinstall hints, rejection of `99.99`, `1`,
`01.0.0`, `00.0.0`, `0.0.0.0`, and `1.2.3-rc1`, and selection of a lone
`0.0.0` tree as first candidate. The repository validator asserts the
strict-version gate and eight-event command-shape consistency instead of only
the cache-path and reinstall-hint fragments.

An isolated Codex CLI 0.149.0 home passes first managed installation of the
0.8.11 versioned cache and archive, a strict second apply no-op, a read-only
no-op, source/staging/live/archive parity across all 15 product files with the
archive index bound to the same manifest, the installed eight-Hook self-test,
`SMOKE_PASS` lifecycle smoke, and no `.git`, `__pycache__`, `.pyc`, or `.pyo`
residue in the new cache or staging trees.

The macOS default home then upgraded the consumed 0.8.10 install to exact
candidate `d7c9b0b5769c110c743f2a20a487ac40078d7713`. The managed upgrade,
strict second apply no-op, read-only audit, 15-product-file
source/staging/live/archive parity, installed eight-Hook self-test, and
`SMOKE_PASS` lifecycle smoke passed. A fresh interactive Codex CLI 0.149.0
task reviewed and trusted exactly eight Hooks without a trust bypass. A second
prompt after trust fired `UserPromptSubmit`, returned
`MACOS_0811_TRUSTED_HOOK_OK`, and persisted schema-7 state with
`integrity=ok`, `R001`, `A001`, and `P0001`; normal exit produced a
`SessionEnd` recovery record, and the private JSON files were mode `0600`.
Fresh task startup and a later `codex plugin list` each pruned historical live
caches to 0.8.11 on this host. The read-only manager named every missing tree,
and managed applies restored all 11 indexed versions from 0.6.1 through
0.8.11 from the intact trusted archive. The final repeated apply was a strict
no-op, and the repository worktree stayed clean.

Native Windows acceptance independently used Windows 10.0.26200.9168,
PowerShell 7.6.4, Python 3.12.10, Git 2.53.0.windows.2, and Codex CLI 0.149.0
against the same exact candidate. Repository/privacy validation, 218 tests,
Ruff, compilation, diff checks, the eight-Hook self-test, and four native
PowerShell resolver groups passed. Six capability-aware skips remained
explicit: three POSIX resolver cases, one POSIX launcher case, and two
symbolic-link cases. The complete invalid-version set was rejected and a lone
`0.0.0` tree was selected correctly.

The Windows default-home upgrade preserved and indexed 0.8.3, 0.8.5, 0.8.6,
0.8.7, and 0.8.8 while adding 0.8.11. The second apply and read-only audit were
no-ops; complete staging/live/archive snapshots were unchanged; all 15 product
files matched source with aggregate SHA-256
`b323df999cb8915dbd24cdbacc0ac337f060604209806aba2365f2ee9864cd82`;
and the installed self-test, lifecycle smoke, archive index, and forbidden-
residue checks passed. A fresh interactive task reviewed and trusted the exact
eight-Hook set without bypass, returned `WINDOWS_0811_TRUSTED_HOOK_OK`, ran
`UserPromptSubmit`, `Stop`, and `SessionEnd` without launcher or code-2
failures, and persisted schema-7 state with `integrity=ok`, active mode, and
`R001`/`A001`/`P0001`. Windows ACLs remained private. This Windows fresh task
did not prune any historical live cache; that native result does not broaden
the macOS pruning observation into a cross-platform guarantee.

PR #15 passes its final 14-check GitHub Actions set: `ubuntu-latest`,
`macos-latest`, and `windows-latest` with Python 3.10, 3.11, 3.12, and 3.13,
plus the HOL Plugin Scanner and plugin scanner. It was fast-forward merged at
exact documentation head `b3637748e858ed5c0f91643f3d3708fd99bc0035` after
the native acceptance evidence was recorded. Main CI and HOL pass at that same
head. The release-status commit, tag automation, annotated tag, GitHub Release,
public release readback, and downstream consumer pin remain separate gates.

## 0.8.9 source-candidate acceptance (2026-08-26)

The macOS source candidate passes repository validation, the tracked-tree
privacy audit, 211 tests with two capability-aware symbolic-link skips, the
eight-Hook self-test on Python 3.12.2, Ruff 0.16.1, external-cache compilation,
commit-identity audit of the unchanged public baseline, and `git diff --check`.

Focused classifier and Stop-path regressions reproduce the review reply that
previously caused a privacy continuation. Short human-readable token examples
and canonical redaction placeholders now yield normally, including with an
authenticated `user_wait` disposition. Whitespace-padded or split values that
collapse to the private-token shape, private directory/session bindings,
private option bindings, and serialized control structures remain sensitive
and fail closed.

An isolated Codex CLI 0.149.0 home passes first managed installation of the
0.8.9 versioned cache and archive. Source, sanitized marketplace staging, live
cache, and trusted archive match across all 15 product files; the installed
eight-Hook self-test and lifecycle smoke pass on Python 3.12.2, with no Git or
bytecode residue. The second and a repeated managed apply both report the
current version and skip cache refresh. Before and after the repeated apply,
the isolated home's 147-file all-file manifest has the same SHA-256 digest.

The macOS default Codex home then applied exact candidate commit
`540c59e78bfb63fd358dbff9f9327917f47831f5`. The managed upgrade preserved
historical live state at managed-apply time, created the 0.8.9 versioned live
cache and trusted archive, and a second apply skipped cache refresh. Sanitized
staging, live cache, and archive each retained the same 48-file all-file
manifest across the strict no-op, with all 15 product files matching source.
Read-only manager audit, installed eight-Hook self-test, lifecycle smoke, and
Git/bytecode residue checks passed.

A fresh interactive Codex CLI 0.149.0 task then ran the installed
`UserPromptSubmit` Hook with explicit activation and displayed classifier
2.3.1. The requested exact reply returned. Private state readback showed schema
7, explicit activation, one prompt, and one classifier-2.3.1 Stop decision with
the expected neutral allow outcome. This native macOS evidence is bound to
`540c59e`; later documentation-only evidence commits do not replace that
runtime provenance. Native Windows, CI, tag, GitHub Release, and downstream
consumer-pin evidence remain pending.

Release-blocking correction (2026-08-26, same day): every preservation claim
above describes managed applies only. Starting a fresh interactive Codex CLI
0.149.0 task on the same macOS default home pruned every historical versioned
live directory under `plugins/cache/codex-context-guard/context-guard/`
(0.6.1 through 0.8.8), keeping only the installed 0.8.9 tree; the hash-indexed
archive stayed intact. An open task whose trusted `PLUGIN_ROOT` pointed at the
pruned 0.8.8 path lost its later Hook invocations until a safe-installer apply
restored that tree from the archive, and starting another fresh task can prune
it again. Historical live-cache retention therefore does not survive host task
starts, PR #15 must not merge or publish this candidate as-is, and the
lifecycle fix is handled by the 0.8.11 release recorded above.

PR #15 at evidence head `fe24aec` passes the complete 12-job GitHub Actions
matrix on `ubuntu-latest`, `macos-latest`, and `windows-latest` with Python
3.10, 3.11, 3.12, and 3.13. The HOL Plugin Scanner and its uploaded plugin
scanner check also pass. Windows runner results are CI evidence only: a native
Windows default-home install, strict no-op, installed lifecycle smoke, and
fresh trusted-Hook task remain separate and have not been performed for 0.8.9.
Tag, GitHub Release, and downstream consumer-pin evidence also remain pending.

## 0.8.8 release acceptance (2026-08-25)

The real macOS default home applied final 0.8.7 release commit
`5c0375eb92e1c03eed0309d570d06380ebcfefe7` through the pinned downstream
manager. The first apply updated checkout, sanitized staging, plugin, live
cache, and archive; the second apply skipped cache refresh. Read-only audit,
eight-Hook self-test, and installed lifecycle smoke passed.

A new interactive Codex CLI 0.149.0 task then displayed and trusted all eight
changed Hooks. Its `UserPromptSubmit` and `Stop` Hooks both exited with code 2.
The Hook command resolved bare `python3` to `/usr/bin/python3` 3.9.6, while the
runtime requires Python 3.10+; running the same installed entry with that
interpreter reproduced the exit exactly. Python 3.12.2 was installed later on
`PATH`, so this is interpreter selection rather than a missing dependency.

The 0.8.8 candidate adds capability-probing POSIX and Windows launchers and a
focused POSIX regression. On macOS with Python 3.12.2, repository/privacy
validation, 209 tests with two capability-aware skips, eight-Hook self-test,
Ruff, external-cache compilation, and diff checks pass. A disposable Codex
home passes first install, strict no-op, read-only audit, installed launcher
self-test, lifecycle smoke, and forbidden-residue checks. A fresh interactive
Codex CLI 0.149.0 task reviewed and trusted all eight candidate Hooks. Its
`UserPromptSubmit` and `Stop` completed without the 0.8.7 code-2 failure, the
requested exact reply returned, and the matching private state file was mode
`0600`. The 0.8.8 live tree retained no Git or bytecode residue.

Native Windows applied exact candidate
`40987d48d6a6f7a8ea8b3ae6e468c472170748a4` through the pinned consumer into
the real Codex home. The managed upgrade created checkout, sanitized staging,
live cache, and archive; the second apply was a strict no-op. Read-only
readback, the eight-Hook self-test, lifecycle smoke, and the PowerShell launcher
passed with Python 3.12.10. A fresh interactive task trusted all eight Hooks;
`UserPromptSubmit` and `Stop` succeeded without code 2 and produced schema-7
private state.

The 0.8.3/0.8.5/0.8.6/0.8.7 historical live trees stayed byte-wise unchanged
across the upgrade. The 0.8.8 smoke left its 41-file live snapshot unchanged;
staging, live cache, and archive each retained 41 files with no `.git`,
`__pycache__`, `.pyc`, or `.pyo`. All 15 product files match across source,
staging, live cache, and archive. Downstream manager, installer, Skill-validator,
and execution-policy contracts passed; the exact upstream suite reported 209
tests with three capability-aware skips on Windows, and exact downstream CI
passed. Exact-candidate PR CI passes the 12-job OS/Python matrix, HOL Scanner,
and plugin scanner. Main/tag automation, the annotated tag, GitHub Release, and
the downstream final release pin remain separate publication evidence.

## 0.8.7 release acceptance (2026-08-25)

Native Windows 0.8.6 stopped after the managed apply created the new checkout,
staging, live cache, and archive but deleted the retained historical 0.8.5
`scripts/__pycache__/context_guard.cpython-312.pyc`. Before apply the file was
338,639 bytes with SHA-256
`323bf8d6fd31f9ae979ec6c5b02d33195a29d5ce985a0bf7c132d19e5262e033`;
after apply it was absent from both the historical live tree and archive. The
Windows operator performed no later no-op, smoke, parity, state, commit, push,
or CI step and retained the resulting 0.8.6 directories for diagnosis.

The 0.8.7 source candidate separates product trust from historical all-file
preservation. Before `codex plugin add`, any indexed historical live tree that
differs from its archive receives an external transaction copy and SHA-256
manifest. The installer restores and verifies that exact live tree after the
Codex cache-root refresh, retains the transaction on incomplete recovery, and
recovers it before a later managed apply. Read-only diagnosis is no-write;
embedded Git metadata, symlinks, product drift, and malformed transaction data
fail closed.

Implementation commit `285c3905bcf20a1c326761cfe719d02c4dcf06c0` passes the
public repository/privacy gates, 206 tests with two capability-aware skips,
eight-Hook self-test, Ruff, external-cache compilation, and diff checks on
macOS with Python 3.12.2. A disposable Codex CLI 0.149.0 home first installs
exact 0.8.6 and archives it, then a direct runtime import creates an actual
339,172-byte historical `.pyc` with SHA-256
`2ac6feb0e4f6d3dd34bfe0a7392cde7b727c6c45dfbb8027551b8cf5fced0588`
only in the old live tree.

The managed candidate upgrade preserves that file's path, size, hash, and the
complete 0.8.6 live-tree all-file SHA-256 snapshot while leaving the 0.8.6
trusted archive product-only. The transaction bundle is absent after verified
restoration. A second candidate apply is a strict no-op; normal read-only
readback and the eight-Hook self-test pass. The installed lifecycle smoke runs
without an outer bytecode guard and leaves the 0.8.7 live all-file snapshot
unchanged; 0.8.7 staging/live/archive remain identical and contain no `.git`,
`__pycache__`, `.pyc`, or `.pyo` residue.

Exact candidate commit `d91a663af20623c1a38d69e3a062903f9e30e673` passes the
12-job PR CI matrix, HOL Scanner, and plugin scanner. Native Windows acceptance
installed that candidate in the real Codex home and preserved the pre-existing
file lists and SHA-256 snapshots for the 0.8.3, 0.8.5, and 0.8.6 historical
live trees. The already-lost 0.8.5 `.pyc` remained absent and was not recreated.
The 0.8.7 smoke left its own all-file snapshot unchanged; source, staging, live
cache, and archive contain the same 13 product files with no forbidden residue.
The downstream acceptance suite passed the upstream 206-test suite with two
capability-aware skips, Windows smoke 2/2, path contracts 5/5, the full
34-Skill validator, and exact downstream CI. Main CI, tag CI, annotated tag,
and GitHub Release remain separate publication evidence.

## 0.8.6 release acceptance (2026-08-25)

Native Windows applied exact public 0.8.5 from the pinned downstream into the
real default Codex home. The 0.8.3 checkout registration migrated to sanitized
0.8.5 staging; the public plugin was installed and enabled; a second apply was
a strict no-op; read-only readback, the eight-Hook self-test, and lifecycle
assertions passed; and source, staging, live-cache, and archive product
manifests each contained the same 13 files and SHA-256 values. The final
acceptance nevertheless failed because the smoke's direct runtime import wrote
`scripts/__pycache__/context_guard.cpython-312.pyc` into the 0.8.5 live cache.
Windows stopped immediately, retained the artifact for diagnosis, and did not
update downstream state or delete historical checkouts, caches, archives, or
private task data.

The 0.8.6 candidate disables bytecode writing inside the smoke's direct import
and restores the prior process setting afterward. Its focused regression
removes the outer environment guard, runs the full smoke against a disposable
plugin root, and requires both `SMOKE_PASS` and the absence of `__pycache__`,
`.pyc`, and `.pyo`. Exact candidate commit
`e28e5aa90016d60d3678d2edc9124fa3e2b7d833` passes the public repository and
privacy gates, 202 tests with two capability-aware skips, source self-test,
Ruff, compilation, and diff checks on macOS with Python 3.12.2. A disposable
Codex CLI 0.149.0 home installs 0.8.6 through sanitized staging, retains
source/staging/live/archive parity, passes installed self-test, and completes a
strict second no-op. With the outer bytecode environment variable explicitly
removed, its full installed smoke passes without changing an all-file live-cache
SHA-256 snapshot or leaving `.git`, `__pycache__`, `.pyc`, or `.pyo` anywhere in
the staging/live/archive roots. Main/tag CI, tag, Release, downstream pinning,
and native Windows 0.8.6 rerun remain separate evidence surfaces. That Windows
rerun later failed at historical-file protection during managed apply, as
recorded in the 0.8.7 candidate section above; it did not reach no-op, smoke,
or parity verification.

## 0.8.5 release acceptance (2026-08-25)

The real macOS pinned downstream 0.8.3-to-0.8.4 consumer apply verified the new public
commit and materialized its immutable checkout, then stopped before marketplace
or plugin mutation because the existing registration named the previous pinned
checkout. The installed public plugin therefore remained at 0.8.3 and private
task data was not changed. This integration failure is distinct from the
successful isolated 0.8.4 install and from CI.

The 0.8.5 candidate recognizes a previous managed commit checkout and its
sanitized staging sibling while rejecting same-identity paths outside the
managed upstream root. Focused manager tests pass for migration, no-write dry
run, unrelated-root rejection, fresh registration, staging parity, and cleanup.
The public repository/privacy gates, 201 tests with two capability-aware skips,
the eight-Hook self-test, Ruff, and compilation pass on macOS with Python
3.12.2.

An isolated consumer first installed exact public 0.8.3, then materialized and
verified exact candidate commit `763d2e5b55c7deef6618562816e08885e0a29956`.
The upgrade repointed the old checkout registration to the new sanitized
staging root, installed 0.8.5, repaired the old live cache from its trusted
archive after the CLI refresh, retained both versioned cache/archive sets, and
passed source/staging/cache parity, installed lifecycle smoke, and the installed
eight-Hook self-test. A second apply was a strict no-op; the normal read-only
consumer path then passed without writes. Staging and live cache carried no
`.git` metadata or leftover temporary directories.

Real default-home migration, main/tag CI, the annotated tag, and GitHub Release
are separate evidence surfaces and must be verified independently.

## 0.8.4 release acceptance (2026-08-25)

Version 0.8.4 is an installer and cache-lifecycle patch. It registers the
marketplace from a sanitized, manifest-verified staging copy instead of the Git
checkout, migrates an existing checkout registration under `--apply`, and gives
read-only checks an actionable repair instruction. Schema 7, execution protocol
1.0.0, Proof protocol 1.0.0, Stop protocol 1.1.0, classifier 2.3.0, Python 3.10+,
and the exact eight-Hook wire are unchanged.

The native Windows report reproduced the original defect in a real Codex home
and verified fresh staging, checkout-to-staging migration, repair from the
trusted archive, strict second-run no-op, read-only diagnosis, and absence of
embedded `.git` or leftover staging temp directories. PR CI passed all 12
OS/Python jobs plus plugin scanning and HOL scanning.

Native macOS source validation passed with Python 3.12.2: repository validation,
the tracked-tree privacy audit, 197 tests with two capability-aware skips, the
eight-Hook self-test, Ruff, compilation with an external bytecode cache, and
`git diff --check`. An isolated Codex home passed first installation as
`context-guard@codex-context-guard` 0.8.4, staging/source and source/cache parity,
strict second-run no-op, installed lifecycle smoke, and the installed eight-Hook
self-test. The disposable absolute path is intentionally not retained.

The fix commit was fast-forwarded to public `main` without generating a new
merge identity. Its 12-job main CI matrix and HOL scan passed. Release-commit
CI, the annotated tag, tag CI, GitHub Release, downstream consumer pin, and
default-home migration are verified separately rather than inferred here.

## 0.8.3 release acceptance (2026-08-24)

Version 0.8.3 is the first completed
Phase 3 implementation with schema 7, execution protocol 1.0.0, classifier
2.3.0, root-only deterministic contract adoption, and semantic native-plan
drift. It retains Proof protocol 1.0.0, Stop protocol 1.1.0, Python 3.10+, and
the exact eight-Hook wire.

Native macOS source validation passed on the candidate worktree with Python
3.12.2: repository validation, tracked-tree privacy audit, 192 tests with two
capability-aware symbolic-link skips, the eight-Hook self-test, Ruff 0.16.1,
compilation with an external bytecode cache, and `git diff --check` all passed.

A disposable Codex home under `/private/tmp` and Codex CLI 0.149.0 passed first
installation as `context-guard@codex-context-guard` 0.8.3, source/cache parity,
strict second-run no-op, installed schema-7 lifecycle smoke, and the installed
eight-Hook self-test. The temporary absolute path is intentionally not retained
as product evidence.

A downstream configuration consumer manager verifies the exact clean Git commit,
origin, manifest repository, and 0.8.3 pin before invoking this installer. The
default Codex home then passes installation, strict second no-op, source
self-test, and plugin-list readback with the public identity enabled. The old
private identity is disabled while its existing versioned live/archive caches,
including 0.8.3, remain present.

Native Windows source validation passes with Python 3.12.10: repository
validation, tracked-tree privacy audit, 192 tests with one capability-aware
symbolic-link skip, the eight-Hook source self-test, Ruff 0.16.1, compilation,
and `git diff --check`. The pinned Windows consumer install verifies the clean
public commit and manifest, installs `context-guard@codex-context-guard` 0.8.3,
passes source/cache/archive parity, the installed schema-7 lifecycle smoke,
the installed eight-Hook self-test, and a second strict no-op. The old private
identity is disabled without deleting its live/archive cache set; SHA-256
snapshots of the public and legacy live/archive trees remain unchanged across
the second manager run.

The candidate source was pushed to public `main` and read back with local
`HEAD == origin/main`. Main CI #79 completed all 12 matrix jobs successfully and
HOL Plugin Scanner #59 also passed for candidate commit `2d1b6ac`.

A normally trusted fresh interactive Codex CLI 0.149.0 task on macOS, without
`--dangerously-bypass-hook-trust`, loaded the public 0.8.3 profile after the
verified Python 3.12.2 interpreter was selected on `PATH`. UserPromptSubmit
adopted revision 1 of a bounded schema-7 contract. Readback reported
`integrity=ok`, an active deterministic candidate, a non-authoritative
natural-language candidate, zero action tickets, zero denials, and a normal
SessionEnd. Main and tag CI/HOL, the annotated tag, and GitHub Release metadata
remain separate publication evidence.

## 0.7.7 release acceptance (2026-08-18)

The release synchronizes the declared shared runtime and transformed
regression contract from its authoritative sibling source. It keeps schema 6,
Proof protocol 1.0.0, Stop protocol 1.1.0, Python 3.10+, and the exact eight-Hook
wire while advancing classifier metadata to 2.2.1.

Native Windows source validation passed the public repository and tracked-tree
privacy audits, sibling parity, 170 tests with one capability-aware symbolic-link
skip, the eight-Hook source self-test, Ruff 0.16.1, compilation, and
`git diff --check` with Python 3.12.10. An isolated Codex CLI 0.146.0 install
passed first install, source/cache parity, strict second-run no-op, the installed
eight-Hook self-test, and lifecycle smoke.

Native macOS passes the same public repository and privacy gates, sibling
parity, 170 tests with two capability-aware skips, the eight-Hook source
self-test, Ruff 0.16.1, compilation, and `git diff --check` with Python 3.12.2.
An isolated Codex CLI 0.146.0 install passes first install, source/cache parity,
strict second-run no-op, the installed eight-Hook self-test, and lifecycle
smoke. A normally trusted public fresh-CLI Hook task was not repeated for this
patch. Main and tag CI/HOL remain separate source-automation evidence and do
not substitute for either native result.

## 0.7.6 release acceptance (2026-08-17)

The public tree now carries the 0.7.6 shared runtime and its regression
contract. The plugin manifest, packaging metadata, public validator, versioning
documentation, and bilingual release notes identify 0.7.6 as the current
published release. The release keeps schema 6, Proof protocol 1.0.0, Stop
protocol 1.1.0, and
the eight-Hook wire; classifier 2.2.0 recognizes plural and quantified
completion claims and explicit first-person reporting while ignoring questions,
trailing negations, attributed speech, and hypotheticals. The Hook entry now
fails closed on Python older than 3.10.

Scoped native Windows verification passed against source commit
`ec7f2ec5e381a23585848e7995cbd9271b9d9e7a`: public repository validation,
tracked-tree audit, sibling parity, 168 tests with one capability-aware skip,
Ruff 0.16.1, and scripts/tests compilation all passed.
An isolated Windows 0.7.6 install also passed first install, strict second-run
no-op, installed eight-Hook self-test, and lifecycle smoke. Native macOS passes
the same public repository gates, 168 tests with two capability-aware skips,
the eight-Hook source self-test, and an isolated first-install/strict-no-op/
installed-lifecycle chain. A normally trusted public fresh-CLI Hook task was
not repeated for this patch. Main and tag CI/HOL are separate source-automation
gates and do not substitute for either native result.

## 0.7.5 synchronized source candidate (2026-08-17)

The public tree now carries the 0.7.5 shared runtime and its regression
contract. The plugin manifest, packaging metadata, public validator, versioning
documentation, and bilingual release notes identify 0.7.5 as the current
unreleased source line while preserving 0.7.3 as the latest published release.
The candidate keeps schema 6, Proof protocol 1.0.0, Stop protocol 1.1.0, and
the eight-Hook wire; classifier 2.1.0 now separates direct current-task
completion assertions from quotations, hypotheticals, and examples, and keeps
later authorized actions visible after a negated clause.

The public source gate passes 132 Hook tests with one Windows-only skip, 23
manager tests with one Windows-only skip, 11 public-contract tests, the complete
sibling shared-core/boundary parity check, the tracked-tree privacy audit, Ruff,
source compilation, and diff checks. The combined public suite reports 166
tests with two capability-aware skips.

The private upstream reports a native Windows 0.7.5 result, but that evidence is
not reused for the public tree. Public source parity, standalone installation,
native macOS/Windows runtime acceptance, CI/HOL, tagging, and release remain
separate gates. No 0.7.5 tag or GitHub Release is claimed here.

## 0.7.3 release differential gate (macOS and Windows, 2026-08-14)

Version 0.7.3 follows a differential audit that found four 0.7.1 regressions:
ordinary `rg` text containing `register-proof` was blocked; qualitative
complete-scope wording was over-enforced; every `PostToolUse` reread up to 2
MiB of transcript; and contract metadata made recovery clipping occur earlier
while allowing the completion rule to be removed. Native 0.7.2 multimodal
acceptance then exposed that denied or out-of-scope mutation wording could
create a false result-readback obligation, and that explicit scope cardinality
must outrank attachment count. The 0.7.3 source requires
current-runtime execution for private-control intent, prompt-constructible
scope, once-per-prompt tool-time transcript reconciliation with forced
lifecycle retries, and a reserved recovery suffix.

The local candidate gate passes 128 private and 128 public Hook tests (one
Windows-only skip in each), 21 private and 22 public manager tests, 10 public
contract tests, export and sibling-parity suites, repository/privacy audits,
compilation, and project-configured Ruff. Isolated private and standalone
installs pass strict second-run no-op and installed lifecycle smokes. The
formal private install creates distinct, source-identical live and archive
0.7.3 trees while preserving 0.7.0/0.7.1/0.7.2. A normally trusted fresh image
task binds an available 64 x 64 PNG to its prompt and, for denied/out-of-scope
mutation wording, enforces only input inspection without a false result
readback obligation. A 2 MiB transcript differential benchmark measures 3.264
ms per steady-state 0.7.3 `PostToolUse` versus 2.267 ms for 0.6.3; the bounded
once-per-prompt scan invariant prevents growth with transcript size after the
first reconciliation. Native Windows independently completed the bounded
0.7.3 source, installation, archive, strict no-op, and installed lifecycle
gates. The annotated `v0.7.3` tag and GitHub Release are created only from the
exact release commit after its source automation passes; tag automation is
tracked separately and does not substitute for either native run.

## 0.7.1 candidate acceptance (macOS, 2026-08-13)

Schema 6 and Proof protocol 1.0.0 add deterministic item, subject, surface,
multimodal asset, visual-readback, and normalized complete-scope obligations.
The 0.7.0 cache was consumed when the first normally trusted image task exposed
late transcript attachment metadata that was registered but not prompt-bound.
That cache remains immutable. Version 0.7.1 reconciles the bounded transcript
before first tool evidence and upgrades only an existing `legacy_fallback` to
an enforced contract; an enforced contract cannot be downgraded.

Native macOS acceptance passes 155 public tests (one capability skip), 123
private Hook tests (one skip), manager and public-contract suites, repository
and privacy audits, Ruff 0.16.1, compilation, six-file byte parity, isolated
private/public first-install and strict no-op lifecycle gates, and installed
private tests. A normally trusted fresh image task binds `M0001` to `P0001`,
shows enforced input-inspection obligations for both requirement and
acceptance, and reports incomplete when no qualifying visual evidence exists.
A real `/compact` resumes through the 0.7.1 SessionStart Hook with the bounded
asset and unresolved obligation retained. No 0.7.x tag or Release is created,
and native Windows 0.7.x acceptance is not claimed.

## 0.6.3 release acceptance (macOS and Windows, 2026-08-12)

Version 0.6.3 keeps schema 5, advances the Stop protocol to 1.1.0, retains
classifier 2.0.0 and the exact eight-Hook wire, and makes the legacy
`continue` disposition advisory. The release acceptance proves that a terminal
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
Windows acceptance independently passes against the same frozen inputs:
113 private and 145 public tests (one capability-aware symlink skip each),
manager/export/parity/boundary and public privacy/identity gates, Ruff 0.16.1,
compilation, installed lifecycle and eight-Hook self-tests, 0.6.1 -> 0.6.2 ->
0.6.3 repair-before-archive chains, and strict second no-ops. Normally trusted
private/public identities pass legacy continue, `user_wait`, completion,
explicit persistence, malformed-control isolation, and manual schema-5
`/compact` recovery. CI did not substitute for these native checks. After the
native gate passed, the 0.6.3 code was merged into `main`; the annotated
`v0.6.3` tag and GitHub Release were created only after the exact release
commit passed the source and tag automation gates.

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
GitHub Release. The 0.6.3 tag and Release received separate authorization in
the release task and were created from the exact final commit only after it
preserved the accepted macOS and Windows runtime evidence, passed all local and
remote packaging gates, passed PR/main CI and HOL, and then passed tag CI.
Compatibility wording must remain bounded by observed evidence.
