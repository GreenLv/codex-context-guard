# Changelog

[简体中文](CHANGELOG.zh-CN.md)

Versions are listed from newest to oldest; unreleased candidates are labeled explicitly. `0.7.7` is the latest published release, while `0.8.3` is an unreleased source candidate. Detailed schema and protocol history lives in [the versioning policy](docs/VERSIONING.md), while test runs and platform limits live in [the local acceptance record](docs/LOCAL_ACCEPTANCE.md).

## How protection evolved

- **0.8.x — keep adopted project instructions and execution plans aligned:** the unreleased line can bind declared instruction sources, including Skill contracts, to a project execution contract and optionally to the current Codex Plan. A later change makes the binding stale instead of silently accepting the old plan.
- **0.7.x — bind evidence to the thing being verified:** check that evidence belongs to the required subject, output surface, and requested scope. This line also added privacy-preserving protection for images and other multimodal inputs by storing hashes and metadata rather than image bytes.
- **0.6.x — verify whether a turn may finish:** distinguish a verified completion checkpoint from “continue”, waiting for the user, waiting for an external result, or deliberately deferred work. `0.6.0` introduced this line but was never released; `0.6.1` was the first published version in the line.
- **0.5.x — explain stop decisions and make upgrades recoverable:** show why Context Guard allowed or stopped a response, and preserve immutable installed Hook versions so a damaged cache can be repaired safely.
- **0.4.x — remember the user's task:** preserve prompts, requirements, corrections, delegated work, and open acceptance items across compaction and resume; do not report the whole task complete while requested work remains.

## 0.8.3 - Unreleased

### Changed

- A long task can now keep a reviewed execution checklist alongside its requirements and evidence. This project execution contract records which instruction sources apply, which phases and gates remain, and whether it should stay aligned with the current Codex Plan.
- The contract starts inactive. Only the user who started the root task can activate a reviewed, project-relative JSON contract with `context-guard adopt`; ordinary prose cannot grant authority.
- If an adopted plan or instruction source changes, Context Guard marks the affected contract records stale. It does not rewrite the Codex Plan, block tools, reserve work automatically, or commit and publish on the user's behalf.

### Technical details

- State schema 7 stores only bounded identifiers, counts, states, and hashes for the execution contract. “Dormant” in design documents means that the storage exists but no contract has been adopted; “stale” means a previously adopted source or plan no longer matches its recorded digest.
- Compatibility fixes from the installed but unpublished 0.7.8–0.8.2 candidates are included without rewriting those immutable installed versions.
- The public repository is now the sole implementation upstream; downstream configuration repositories consume an exact version and commit.

### Validation status

- Native macOS and Windows source checks, privacy audits, the 192-test suite, eight-Hook self-test, compilation, and isolated installation/upgrade checks passed, with platform-specific symbolic-link skips recorded in the acceptance log.
- Exact-commit downstream installation and source/cache/archive parity passed on both platforms. Fresh-task Hook trust, CI, tag, and GitHub Release remain separate gates; this candidate is not yet a published release.

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
