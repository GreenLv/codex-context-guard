# Changelog

[简体中文](CHANGELOG.zh-CN.md)

Versions are listed from newest to oldest; unreleased candidates are labeled explicitly. `0.8.5` is the latest published release. Detailed schema and protocol history lives in [the versioning policy](docs/VERSIONING.md), while test runs and platform limits live in [the local acceptance record](docs/LOCAL_ACCEPTANCE.md).

## How protection evolved

- **0.8.x — separate what user instructions, Skills, and the model plan may decide:** the user defines the task and write authority; adopted `AGENTS.md` or Skills define the workflow; Codex Plan is a revisable execution arrangement; and tool, file, image, or public-readback results provide factual evidence. Version 0.8.3 records these sources and an optional plan binding, requests review after drift, and does not turn them into new authority or tool interception.
- **0.7.x — bind evidence to the thing being verified:** check that evidence belongs to the required item, file or page, and complete requested scope. This line also added privacy-preserving protection for images and other multimodal inputs. It stores hashes and bounded metadata, and an image-editing task requires inspection of the changed image rather than only a successful tool call.
- **0.6.x — separate “the task is complete” from “this turn may stop”:** only a verified completion checkpoint marks the task complete. Waiting for the user, waiting for an external result, or explicitly deferring work can end the current turn while requirements remain open. `0.6.0` introduced this line but was never released; `0.6.1` was the first published version in the line.
- **0.5.x — explain stop decisions and make upgrades recoverable:** show why Context Guard allowed or stopped a response, and preserve immutable installed Hook versions so a damaged cache can be repaired safely.
- **0.4.x — remember the user's task:** preserve prompts, requirements, corrections, delegated work, and open acceptance items across compaction and resume; do not report the whole task complete while requested work remains.

## 0.8.6 - Unreleased

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
- Candidate source, isolated install, no-bytecode lifecycle, CI, tag, Release, downstream pin, and native Windows rerun remain separate gates.

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
