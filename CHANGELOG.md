# Changelog

[简体中文](CHANGELOG.zh-CN.md)

Versions are listed from newest to oldest; unreleased candidates are labeled explicitly. `0.8.12` is the latest published release. Detailed schema and protocol history lives in [the versioning policy](docs/VERSIONING.md), while test runs and platform limits live in [the local acceptance record](docs/LOCAL_ACCEPTANCE.md).

## How protection evolved

- **0.8.x — separate what user instructions, Skills, and the model plan may decide:** the user defines the task and write authority; adopted `AGENTS.md` or Skills define the workflow; Codex Plan is a revisable execution arrangement; and tool, file, image, or public-readback results provide factual evidence. Version 0.8.3 records these sources and an optional plan binding, requests review after drift, and does not turn them into new authority or tool interception.
- **0.7.x — bind evidence to the thing being verified:** check that evidence belongs to the required item, file or page, and complete requested scope. This line also added privacy-preserving protection for images and other multimodal inputs. It stores hashes and bounded metadata, and an image-editing task requires inspection of the changed image rather than only a successful tool call.
- **0.6.x — separate “the task is complete” from “this turn may stop”:** only a verified completion checkpoint marks the task complete. Waiting for the user, waiting for an external result, or explicitly deferring work can end the current turn while requirements remain open. `0.6.0` introduced this line but was never released; `0.6.1` was the first published version in the line.
- **0.5.x — explain stop decisions and make upgrades recoverable:** show why Context Guard allowed or stopped a response, and preserve immutable installed Hook versions so a damaged cache can be repaired safely.
- **0.4.x — remember the user's task:** preserve prompts, requirements, corrections, delegated work, and open acceptance items across compaction and resume; do not report the whole task complete while requested work remains.

## 0.9.1 - Unreleased

### Highlights

- Stop protocol 2.0.0 makes an authenticated, full-coverage checkpoint the only authority that can mark a task complete; completion wording can no longer force a continuation or mutate pending state.
- Privacy, state integrity, invalid or stale control, and explicit user-persistence failures remain fail-closed hard gates, while typed waits and safe default yields preserve unresolved work.
- A maintainer-local append-only incident corpus and reviewed public fixtures replace repeated wording patches with reproducible protocol and regression evidence.

### Changes

- Classifier 2.3.2 remains unchanged and records `observed_outcome` for diagnosis only. New authoritative decision sources are `protocol_default` and `protocol_user_persistence`; historical `nlp_hard_gate` records remain readable but are not generated.
- Stop 1.1 in-flight controls are discarded during load, while requirements, evidence, proofs, and bounded decision history remain intact. Schema 7, Proof protocol 1.0.0, Execution protocol 1.0.0, Python 3.10+, and the eight-Hook wire remain unchanged.
- `scripts/incident_corpus.py` provides standard-library-only `ingest`, `validate`, `summarize`, `benchmark`, and `export-public` commands. CI reads only manually reviewed, sanitized fixtures and never the private corpus.
- Incident-corpus directories and files retain exact `0700`/`0600` modes on POSIX. On Windows, the tool applies and verifies a protected ACL limited to the current user, `SYSTEM`, and the built-in Administrators group; inability to establish that boundary fails closed instead of treating POSIX mode bits as Windows privacy evidence.
- The unpublished 0.9.0 candidate introduced Stop protocol 2.0.0 and was consumed during native macOS acceptance. Its installed caches remain immutable; 0.9.1 carries the protocol forward with the Windows ACL correction instead of replacing 0.9.0 bytes in place.
- Managed marketplace staging excludes local environment, test/lint cache, and build-output directories so generated files cannot leak into a versioned plugin cache.

### Validation

- The fixed public incident manifest contains eight reviewed fixtures across eight root-cause families. The immutable 0.8.12 runtime reproduces two false continuations; the 0.9 candidate produces zero and passes all eight authority expectations while reporting diagnostic accuracy separately.
- A fixed seed exercises 10,000 control transitions across English, Chinese, quotation, code, hypothetical, negated, first-person, and attributed speech. Exact 0.9.1 candidate `02e7f57` passes the complete macOS source suite, isolated and default-home installation, strict no-op, parity, smoke, historical-cache recovery, and native fresh-Hook gates. Native Windows, CI, tag, and Release remain pending in the [0.9 development plan](docs/DEVELOPMENT_PLAN_0.9.md).

## 0.8.12 - 2026-08-27

### Highlights

- Stop no longer treats a quoted completion phrase labeled as a kind of statement, such as `“任务已完成”类声明`, as the assistant's own whole-task completion claim.
- Direct completion assertions remain gated, including standalone quoted assertions and explicit first-person confirmations.
- Schema 7, the Proof, Stop, and Execution protocols, Python 3.10+, and the eight Hook events are unchanged.

### Changes

- Classifier 2.3.2 recognizes a bounded Chinese meta-discussion suffix after a quoted completion phrase instead of weakening all quoted completion handling.
- The plugin version advances because installed Hook runtime bytes are immutable; published 0.8.11 caches remain unchanged.

### Validation

- Focused source regressions replay the reported Stop decision and preserve direct Chinese completion claims. Repository and privacy checks, 219 tests with five capability-aware skips, the eight-Hook self-test, Ruff, external-cache compilation, and `git diff --check` pass on macOS.
- Exact candidate `c66ac824f0d9d2015f1725417a2e50f5a96f31da` passes managed installation, strict repeat/no-op readback, installed self-test, lifecycle smoke, and fresh trusted eight-Hook tasks on native macOS and Windows. Both tasks persisted clean schema-7 state and `SessionEnd` recovery after normal exit. The release-status successor changes documentation and public-contract tests only.
- PR automation passes the 12-job OS/Python matrix, HOL Plugin Scanner, and plugin scanner. Main and tag automation, the annotated tag, GitHub Release, public readback, and downstream adoption are verified as separate release surfaces.

## 0.8.11 - 2026-08-27

### Highlights

- Open tasks keep their Hooks when Codex removes an older plugin cache: the Hook first uses its original plugin directory, then falls back to the newest valid managed copy.
- Stop no longer treats clearly redacted values or short, readable token examples as leaked private metadata. Values that look like real control tokens remain blocked.
- When historical caches are missing, the installer now explains what happened and tells the user how to restore them.

### Changes

- POSIX and Windows Hooks accept fallback directories only when they use an exact `X.Y.Z` version without leading zeros and are not symbolic links. A rescued task may therefore use a newer runtime than it first trusted; exact historical restoration still comes only from the trusted archive. If no valid copy survives, the Hook exits with a repair hint instead of running an unknown path.
- The privacy classifier now checks the value of a serialized `token` field instead of rejecting the field name alone. Redaction placeholders and readable examples are allowed; disguised or real-looking private values still fail closed.
- This release includes the fixes from the consumed, unpublished 0.8.9 and 0.8.10 candidates. Their installed caches remain unchanged. Schema 7, existing protocols, Python 3.10+, and the eight Hook events are unchanged.

### Validation

- Repository and privacy checks, 218 tests, lint, compilation, installed self-tests, lifecycle smoke tests, strict reinstall no-ops, and source/cache/archive parity pass. macOS and Windows also pass fresh interactive Hook trust on Codex CLI 0.149.0.
- macOS reproduced the host cache cleanup and restored every indexed version from the trusted archive. The Windows fresh task did not remove its historical caches, so this cleanup is not claimed as universal behavior.
- PR automation passes the 12-job OS/Python matrix, HOL Plugin Scanner, and plugin scanner. Main and tag automation, the annotated tag, GitHub Release, and downstream consumer pin are checked as separate release gates. See [the acceptance record](docs/LOCAL_ACCEPTANCE.md) for exact environments, skips, commits, and hashes.

## 0.8.8 - 2026-08-25

### Highlights

- Hooks now select an available Python 3.10+ interpreter instead of blindly using the first `python3` or `python` on `PATH`.
- A supported interpreter later on `PATH` is used when macOS resolves bare `python3` to Apple's unsupported Python 3.9; if none is available, the launcher fails closed with an actionable stderr message.
- POSIX and Windows launchers preserve the existing eight-event Hook protocol, standard-library-only runtime, stdin/stdout contract, and private-state behavior.

### Changes

- POSIX Hooks call a small `sh` launcher that probes versioned Python commands before the generic names. Windows Hooks validate the active generic command first for fast common-case startup, then try versioned commands and `py -3.x` fallbacks.
- Focused regression coverage places an unsupported `python3` before a supported `python3.12` and requires the launcher to skip the former and pass the eight-Hook self-test with the latter.

### Validation

- Native macOS 0.8.7 installation, strict no-op, read-only audit, installed lifecycle smoke, and eight-Hook self-test passed at the final release pin. A newly trusted interactive Hook then failed because the host resolved bare `python3` to `/usr/bin/python3` 3.9.6; direct reproduction returned the same Python 3.10+ guard failure.
- The candidate passes repository/privacy validation, 209 tests with two capability-aware skips, eight-Hook self-test, Ruff, external-cache compilation, and diff checks on macOS. A disposable Codex home passes first install, strict no-op, read-only audit, launcher self-test, lifecycle smoke, and forbidden-residue checks.
- A fresh interactive Codex CLI 0.149.0 task reviewed and trusted all eight candidate Hooks. `UserPromptSubmit` and `Stop` ran without the earlier code-2 failure, the exact fixed reply returned, private state was written with mode `0600`, and the 0.8.8 live cache retained no Git or bytecode residue.
- Native Windows applied exact candidate `40987d48d6a6f7a8ea8b3ae6e468c472170748a4` through the pinned consumer. The managed upgrade, strict second no-op, read-only readback, eight-Hook self-test, lifecycle smoke, PowerShell launcher, and fresh interactive trust all passed. Historical 0.8.3/0.8.5/0.8.6/0.8.7 live trees stayed byte-wise unchanged; the new staging/live/archive trees each retained 41 files with no Git or bytecode residue, and all 15 product files matched across source, staging, live cache, and archive.
- Exact candidate PR automation passes the 12-job OS/Python matrix, HOL Scanner, and plugin scanner. Main and tag automation, the annotated tag, GitHub Release readback, and the downstream final release pin are verified separately from native runtime acceptance.

## 0.8.7 - 2026-08-25

### Highlights

- A plugin upgrade now preserves historical live-cache files that are outside the trusted product manifest, including lifecycle-generated `.pyc` evidence, even when Codex replaces the entire plugin cache root.
- Product archives remain product-only trust authorities. Historical non-product differences are carried through a separate SHA-256-bound transaction and restored to the same versioned live path without entering the trusted archive.
- An interrupted transaction fails closed on read-only inspection and is recovered before the next managed `--apply`. Invalid manifests, embedded Git metadata, and symlinks are rejected before the destructive plugin refresh.

### Changes

- Before `codex plugin add`, the installer compares each indexed historical live tree with its archive using an all-file manifest. Only differing historical trees receive a transaction backup.
- After Codex refreshes the cache root, the installer restores and verifies the exact historical file trees, retains the backup if verification cannot complete, and removes it only after successful restoration.
- Focused regressions cover exact bytecode preservation, failed upgrades, interrupted recovery, read-only no-write behavior, and symlink rejection. Schema 7, the eight-Hook wire, runtime behavior, private data, and product archive hashes are unchanged.

### Validation

- The public repository/privacy gates, 206 tests with two capability-aware skips, eight-Hook self-test, Ruff, external-cache compilation, and diff checks pass on macOS. A real Codex CLI 0.149.0 isolated 0.8.6-to-0.8.7 upgrade preserves an actual 339,172-byte historical `.pyc` and the complete old live-tree SHA-256 snapshot while keeping the old trusted archive product-only.
- The isolated candidate also passes strict second apply no-op, read-only readback, installed self-test, lifecycle smoke without an outer bytecode guard, and staging/live/archive parity with no transaction or bytecode residue in the new version. PR CI passes the 12-job OS/Python matrix, HOL Scanner, and plugin scanner.
- Native Windows acceptance installed the exact candidate in the real Codex home without changing any pre-existing 0.8.3, 0.8.5, or 0.8.6 historical live-tree snapshot. The 0.8.7 smoke left its all-file snapshot unchanged; all 13 product files match across source, staging, live cache, and archive with no forbidden residue. The already-lost 0.8.5 `.pyc` was not recreated or misreported as recovered. The exact downstream acceptance commit and CI passed separately.

## 0.8.6 - 2026-08-25

### Highlights

- The installed lifecycle smoke no longer writes `__pycache__` or `.pyc` files into an immutable plugin root when its caller has not set `PYTHONDONTWRITEBYTECODE`.
- Bytecode suppression is scoped to the smoke process's direct validation import. Hook subprocesses retain their existing no-bytecode environment, and the installed runtime, private data, cache, and archive contracts are otherwise unchanged.
- Native-platform acceptance can now require both a passing lifecycle smoke and a byte-for-byte clean product root without relying on an outer `python -B` workaround.

### Changes

- The smoke temporarily sets `sys.dont_write_bytecode` only while loading the installed runtime module, then restores the caller's process setting.
- A focused regression removes the outer `PYTHONDONTWRITEBYTECODE` variable, runs the full installed lifecycle smoke against a disposable plugin root, and rejects any resulting `__pycache__`, `.pyc`, or `.pyo` artifact.
- Schema 7, all protocol and classifier versions, the eight-Hook wire, marketplace migration, and cache/archive manifests are unchanged.

### Validation

- Native Windows 0.8.5 successfully completed the managed 0.8.3-to-0.8.5 migration, strict no-op, read-only readback, eight-Hook self-test, lifecycle assertions, and manifest parity, but correctly failed final acceptance when the smoke's direct import wrote one `.pyc` into the live cache. It stopped without deleting that artifact or updating downstream state.
- The public repository/privacy gates, 202 tests with two capability-aware skips, eight-Hook self-test, Ruff, compilation, and an exact-candidate isolated 0.8.6 install pass on macOS. Its second apply is a strict no-op; a full smoke without the outer bytecode environment guard leaves an all-file SHA-256 snapshot unchanged; and source, staging, live cache, and archive remain byte-identical with no Git or bytecode residue.
- Main/tag CI, the annotated tag, GitHub Release, and downstream pin passed as separate surfaces. Native Windows 0.8.6 later failed before no-op and lifecycle verification because the managed upgrade replaced the cache root and restored only trusted product files, silently dropping the retained 0.8.5 `.pyc` evidence. Version 0.8.7 addresses that separate historical-file preservation defect.

## 0.8.5 - 2026-08-25

### Highlights

- Pinned consumers can now migrate from a previous immutable checkout or its sanitized staging root when the new release uses a different commit-addressed directory.
- Migration remains narrowly bounded to Context Guard roots under the managed `CODEX_HOME/upstreams/context-guard` directory whose manifest repository matches the current product. Same-identity paths elsewhere are still rejected.
- Read-only checks report the required `--apply` migration without changing marketplace, staging, plugin, cache, archive, or private task data.

### Changes

- Version 0.8.4 introduced sanitized staging but recognized only the current checkout path. A pinned downstream upgrade therefore stopped before marketplace mutation when the existing registration still named the previous pinned commit.
- The managed-root recognizer accepts both a 40-character lowercase commit directory and its `.marketplace` staging sibling, preventing the same integration failure on later pin raises.
- Schema 7, all protocol and classifier versions, the eight-Hook wire, and the cache/archive trust model are unchanged.

### Validation

- Focused regressions cover previous pinned checkouts, previous managed staging roots, read-only no-write behavior, unrelated-path rejection, current-checkout migration, fresh registration, staging parity, and temporary-directory cleanup.
- The public repository/privacy gates, 201 tests with two capability-aware skips, eight-Hook self-test, Ruff, and compilation pass. An exact-commit isolated pinned consumer migrated from 0.8.3 to 0.8.5, preserved the old cache/archive, passed installed lifecycle and self-test, and ended with a strict no-op plus successful read-only readback.
- Real default-home migration, main/tag CI, the annotated tag, and GitHub Release are separate acceptance surfaces and do not substitute for the isolated consumer evidence above.

## 0.8.4 - 2026-08-25

### Highlights

- Context Guard now registers its marketplace from a sanitized staging copy instead of an immutable Git checkout, preventing Codex cache refreshes from copying `.git` metadata into the live plugin cache.
- Existing checkout-based registrations migrate with one managed `--apply` run. The same run repairs an already-affected live cache from its trusted archive without deleting historical versions or private task data.
- Read-only checks remain read-only: when migration or repair is needed, they fail with an actionable `--apply` instruction instead of silently changing the installation.

### Changes

- Staging uses the same product-tree ignore rules and manifest as cache verification, rejects embedded Git metadata, replaces stale staging atomically, and cleans temporary directories on both success and failure.
- Marketplace registration verifies the final staging path after a fresh add or checkout-to-staging migration. A current sanitized registration is idempotent.
- This patch changes only installation and cache lifecycle behavior. Schema 7, execution protocol 1.0.0, Proof protocol 1.0.0, Stop protocol 1.1.0, classifier 2.3.0, and the eight-Hook wire remain unchanged.

### Validation

- Native Windows reproduction and real-CLI end-to-end testing verified fresh staging, checkout migration, live-cache repair, strict second-run no-op, read-only diagnosis, and absence of `.git` or leftover staging temp directories.
- Native macOS source validation passed the public repository/privacy gates, 197 tests with two capability-aware skips, the eight-Hook self-test, Ruff, compilation, and an isolated install/no-op/lifecycle chain for the 0.8.4 candidate.
- PR and merged-main CI passed the 12-job OS/Python matrix and HOL scanning. Tag CI, the annotated tag, and GitHub Release remain separate publication facts.

## 0.8.3 - 2026-08-24

### Highlights

- Version 0.8.3 records different sources separately: user instructions define the task and write authority; `AGENTS.md` and selected Skills define the workflow; Codex Plan describes revisable execution steps; and tool, file, image, or public-readback results provide factual evidence. The latter three cannot expand user authority.
- For example, adopting a publishing Skill can record the exact Skill and version, the current phase, and an optional Codex Plan binding. If the Skill or Plan later changes, the old binding is marked for review instead of being followed silently.
- Only the user who started the root task can explicitly adopt this project contract. Version 0.8.3 records, restores, and checks it at completion; it does not rewrite Codex Plan, intercept tools before use, publish automatically, or grant new authority.

### Changes

- State schema 7 stores only bounded identifiers, counts, states, and hashes for the execution contract. “Dormant” in design documents means that the storage exists but no contract has been adopted; “stale” means a previously adopted source or plan no longer matches its recorded digest.
- Compatibility fixes from the installed but unpublished 0.7.8–0.8.2 candidates are included without rewriting those immutable installed versions.
- The public repository is now the sole implementation upstream; downstream configuration repositories consume an exact version and commit.

### Validation

- Native macOS and Windows source checks, privacy audits, the 192-test suite, eight-Hook self-test, compilation, and isolated installation/upgrade checks passed, with platform-specific symbolic-link skips recorded in the acceptance log.
- Exact-commit downstream installation and source/cache/archive parity passed on both platforms. A normally trusted fresh Codex CLI 0.149.0 task on macOS, without trust bypass and with Python 3.12.2 selected, adopted a schema-7 contract with integrity intact: the deterministic candidate became active, the natural-language candidate remained non-authoritative, and no action ticket was created.
- Main and tag CI/HOL, the annotated tag, and the GitHub Release remain separately verified publication facts; they do not substitute for native runtime evidence.

## 0.7.7 - 2026-08-18

### Fixed

- Reduced false verification obligations: ordinary slash-delimited prose and URL fragments are no longer mistaken for local paths, and the general Chinese word for “apply” no longer implies that a UI result must exist.
- A successful `view_image` result carrying a valid image data URL now counts as visual evidence instead of remaining unknown.

### Technical details

- This patch keeps the 0.7 evidence model unchanged and advances only the subject, surface, and visual-result classifier to 2.2.1.
- Native macOS and Windows source, install, archive, no-op, and lifecycle checks passed. See the acceptance record for the exact platform scope.

## 0.7.6 - 2026-08-17

### Fixed

- Context Guard more reliably distinguishes a real “the task is complete” claim from a question, quotation, hypothetical example, trailing negation, or report about somebody else's statement.
- Python versions older than 3.10 now fail closed instead of running an unsupported Hook runtime.

### Technical details

- The 0.7.4–0.7.6 classifier patches refined completion and remaining-work detection without changing the evidence model or Hook events.
- Native macOS and Windows source and isolated lifecycle checks passed; CI and Hook trust remain separate evidence scopes.

## 0.7.3 - 2026-08-14

### Added

- Evidence can be tied to the exact requirement, subject, output surface, requested scope, and required visual readback before an item is considered complete.
- Images and other multimodal inputs are tracked with hashes and bounded metadata; Context Guard does not copy image bytes into its private ledger or recovery packets.

### Fixed

- Visual readback is required only for an affirmative, authorized mutation request. Explicit requested counts take precedence over the number of attached inputs.
- Unsupported cases fall back visibly to the earlier checkpoint behavior instead of claiming stronger verification than the available evidence supports.

### Technical details

- This was the first published 0.7 release. The internal names are state schema 6 and Proof protocol 1.0.0.
- Native macOS and Windows source, installation, archive, no-op, and lifecycle checks passed.

## 0.6.3 - 2026-08-12

### Fixed

- Continuing work is now advisory rather than a way to override a terminal safety decision; only a verified completion checkpoint or explicit persistence request can demand another correction turn.
- Documentation edits and ordinary searches no longer look like private control commands merely because they contain shell-like text.
- Upgrades repair a damaged installed cache from its trusted archive before considering unindexed copies.

### Technical details

- This patch finalized the one-way-safe 0.6 turn-control behavior and hardened cache repair. Native macOS and Windows acceptance passed.

## 0.6.1 - 2026-08-11

### Added

- A task can be marked complete only from a verified checkpoint. Other endings are recorded explicitly as continue, wait for the user, wait for an external result, or defer the remaining work.
- Raw command output can now provide the same verifiable success receipt as a structured tool result.

### Release note

- The unreleased 0.6.0 candidate introduced this turn-control model but its raw-output receipt could not prove success. Its version remains consumed and immutable; 0.6.1 was the first published release in the series.

## 0.5.1 - 2026-08-10

### Fixed

- Explicitly handing control to the user is no longer confused with work the assistant has promised to do itself.
- Open-item counts are recalculated when state is loaded or saved, preventing stale counts from surviving an upgrade.
- A same-version installed cache is trusted only after its source and archive integrity are verified.

## 0.5.0 - 2026-08-09

### Added

- `context-guard diagnose` explains the latest stop decision with bounded, privacy-preserving records instead of requiring maintainers to infer it from raw task text.
- Installed Hook versions are archived with hashes so older tasks can keep using their original runtime and damaged live caches can be repaired from a trusted copy.

## 0.4.16 - 2026-08-09

### Fixed

- A bounded review, test, local commit, or reporting phase may end after clearly leaving a later phase unresolved, while a request to continue, push, publish, deploy, or run CI still keeps the whole-task completion gate active.
- Explicit restrictions such as “do not push” are treated as denied authority; missing or mismatched prompt history fails closed.

## 0.4.13 - 2026-08-08

### Fixed

- Status-only replies about submitted reviews, policy holds, platform choices, or intentionally unchanged repositories can end safely without being mistaken for a whole-task completion claim.

## 0.4.12 - 2026-08-08

### Fixed

- Waiting for a user login, publishing configuration, deployment approval, or another explicit user action can end the current turn safely. Merely listing work that the assistant still owns cannot.

## 0.4.10 - 2026-08-07

### Documentation and distribution

- Added the plugin icon, pinned release checks, bilingual lifecycle diagrams, and a complete compaction-recovery example.
- Native Windows installation, Hook trust, and manual compaction recovery were verified in addition to repository checks.

## 0.4.9 - 2026-08-06

### Fixed

- The installer now routes every Codex subprocess through the requested isolated home instead of accidentally using the caller's default Codex directory.

### Platform scope

- macOS completed native Hook trust and manual compaction recovery. Windows was CI-only at release and received native validation later; Linux remained CI and isolated-lifecycle only.

## 0.4.8 - superseded release candidate

### Included

- The initial public candidate preserved prompts, requirements, corrections, delegated work, evidence, and open completion conditions across compaction and resume.
- It also introduced bounded recovery, a read-only Codex Plan mirror, safe local installation, and immutable versioned Hook caches.

This candidate was not tagged. Version 0.4.9 superseded it with the installer isolation fix and completed standalone runtime gate.
