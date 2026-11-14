# Changelog

[简体中文](CHANGELOG.zh-CN.md)

Versions are listed newest first. See [GitHub Releases](https://github.com/GreenLv/codex-context-guard/releases) for published versions and [local acceptance](docs/LOCAL_ACCEPTANCE.md) for test results and platform limits. The [original detailed changelog](https://github.com/GreenLv/codex-context-guard/blob/1d5a0a0e5ddbefad5ee7fca778793d56b83d4081/CHANGELOG.md) preserves the earlier implementation and validation notes.

## Unreleased

### Highlights

- A daily upgrade batch now continues with one same command. The maintained tool derives the next pending stage from the batch's saved receipts, so prepare → apply → verify no longer needs per-stage retyping; each operator pause (quit the Desktop host, review the Hooks) resumes with the same command. [Daily upgrade tool](tools/validation/DAILY_UPGRADE.md)
- When a host auto-update changes the Desktop executable bytes after preparation, a controlled rebind re-identifies that same-path executable, keeps every prior receipt untouched, and writes the next numbered prepare receipt bound to the new host identity. Any other input change (CLI, artifact, plan, helper closure) still refuses with its own category and needs a fresh reviewed batch.

### Changes

- Candidate CI consumes an already passed full run on the exact commit. A new reuse job re-derives the prior run's full-coverage job evidence through the official Actions API, verifies the escrow artifact receipt against this checkout when it exists, and uploads a `cg-ci-reuse-evidence/v1` receipt; the required summary still demands classification, the static gate and the reuse evidence, and any failed job anywhere still fails the summary. Missing or mismatched evidence falls back to the ordinary lanes. [CI policy](docs/CI_POLICY.md)
- These are source-checkout operator and CI changes. The nine Hooks, state schema, public protocols, runtime bytes and installed behavior are unchanged, and existing 0.17.3 installations need no action.


## 0.17.3 — 2026-11-14

### Highlights

- Maintainers can prepare, apply and verify a daily installation upgrade through one maintained tool on macOS and Windows. Saved stage results let an interrupted batch continue without repeating a completed removal or installation. [Daily upgrade tool](https://github.com/GreenLv/codex-context-guard/blob/v0.17.3/tools/validation/DAILY_UPGRADE.md)
- Before replacing an existing installation, the tool checks the actual Desktop executable and requires it to be stopped. Prepare the batch first, quit Desktop once when required, then continue with the same batch. Normal Hook review remains part of the upgrade.

### Changes

- Verification compares the installed files with the selected release and checks all nine enabled, trusted Context Guard Hooks through a fresh client. This observation does not identify the runtime already held in an existing Desktop process.
- The new operator tools live in the source checkout, rather than the plugin cache. Existing 0.17.2 installations need no urgent runtime update: the nine Hooks, task-state format, automatic cleanup and explicit cleanup settings keep their existing behavior.

### Validation

- The [release acceptance report](https://github.com/GreenLv/codex-context-guard/releases/download/v0.17.3/context-guard-0.17.3-acceptance.json) identifies the source, package and platform results. Daily Desktop adoption is recorded separately.


## 0.17.2 — 2026-11-11

### Highlights

- Context Guard automatically maintains its own session records, leaving Codex chats and session history untouched. Without a retention policy, its records for sessions that ended more than 30 days ago can move to a recoverable quarantine. Later ordinary use can permanently delete those records after at least seven days there.
- Explicit retention settings continue to apply. A disabled policy, custom period, quarantine-only setting, or durable opt-out takes precedence. A damaged or unreadable policy does not authorize deletion. A missing policy uses the automatic default, which permits permanent deletion after quarantine.
- You can upgrade `context-guard@codex-context-guard` from 0.17.1 in place. Finish tasks that still need the old Hook first, or keep them in a separate Codex environment. A 0.17.1 scheduler disable alone did not record a durable opt-out. If you want cleanup to remain off, the upgrade guide explains how to disable it before and after upgrading. [Upgrade guide](docs/UPGRADE_0_17_2.md)

### Changes

- After saving a session, SessionEnd can dispatch a bounded background maintenance pass. Later ordinary use advances eligible quarantined records toward permanent deletion. Scheduled maintenance remains an additional choice.
- The manual cleanup command previews by default. The upgrade guide and [session storage](docs/SESSION_STORAGE.md) explain how to inspect a policy, turn off automatic maintenance, and restore eligible quarantined records.
- In the native upgrade runner, a timed-out Hook review can resume a finish-old upgrade from its saved stage. The verifier checks the old and new process records separately. The migration tool can regenerate a missing summary from its saved transaction records.

### Validation

- The [release acceptance report](https://github.com/GreenLv/codex-context-guard/releases/download/v0.17.2/context-guard-0.17.2-acceptance.json) records the exact ZIP, the isolated upgrade and the platform checks. Daily adoption has separate evidence.

## 0.17.1 — 2026-11-09

### Highlights

- If you installed 0.16.1 from the public ZIP or its local wrapper, switch to the stable plugin entry, `context-guard@codex-context-guard`. If you already use that entry on 0.17.0, upgrade it in place. Before changing either installation, finish tasks that still need the old plugin or keep them in a separately configured Codex environment. The guide also covers the 0.15.1 route. [Upgrade guide](docs/UPGRADE_0_17_1.md)
- Installing 0.17.1 leaves your Context Guard records where they are. If you want to look up an older task from the new entry, use the migration tool to preview and copy records in the `sessions-v2` format on the same machine. Older-format records stay with the original plugin. [Migration tool](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md)
- If both entries have different records for the same session ID, the tool keeps the destination record and saves the incoming copy separately for review. Undo removes only copies from that migration whose contents are still the same.

### Changes

- Maintainers can run the same upgrade checks through POSIX sh or PowerShell 5.1/7. Windows checks cover a PowerShell location that differs from the process directory and distinguish access granted to a named user from rights granted to the owner. [Native upgrade checks](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/validation/NATIVE_UPGRADE_ACCEPTANCE.md)

### Validation

- The final ZIP passed upgrades from the 0.16.1 wrapper, the 0.17.0 stable entry, and 0.15.1 in isolated Codex CLI environments on macOS and Windows. On each platform, a separate test copied and removed sample session records. Daily Desktop use and migration of existing daily records have separate acceptance records. [Release acceptance](https://github.com/GreenLv/codex-context-guard/releases/download/v0.17.1/context-guard-0.17.1-acceptance.json)

## 0.17.0 — 2026-11-06

### Highlights

- Planning an edit no longer makes Context Guard treat the edit as requested work. An explicit request to make the change remains open until it is done.
- Terminal checks recognize Codex Desktop's `aggregated_output` as well as `stdout`. They still verify the command, working directory, status and exit code.
- Session cleanup returns as an opt-in maintenance command. Preview is the default. After you enable the policy and apply a selection, the default settings let eligible sessions move to recoverable quarantine at least 30 days after ending. A later apply can permanently delete them after seven days in quarantine. SessionEnd does not run cleanup.
- New installations use the stable marketplace `codex-context-guard`. Before switching a HOME, finish tasks that need the 0.16.1 runtime or keep them in a separate HOME. Keeping old cache files alone does not establish which Hook an old task loads.

### Changes

- Cleanup checks each selected directory's identity before moving, restoring or deleting it. If creation identity is unavailable or has changed, the directory stays protected. Interruptions retain recovery records.
- The scheduler is enabled and disabled explicitly through macOS launchd or Windows Task Scheduler. Installing the plugin enables neither the scheduler nor a retention policy.
- The upgrade does not move existing session data or consumed caches. See [session storage](docs/SESSION_STORAGE.md) and the [stable marketplace identity contract](tools/validation/STABLE_MARKETPLACE_IDENTITY.md) before changing an existing HOME.

### Validation

- Source, historical regression, installation, performance, native macOS and Windows behavior, and publication evidence are recorded separately. Earlier failed Windows and Linux candidate runs retain their original results; repaired source checks do not replace native tests. See [local acceptance](docs/LOCAL_ACCEPTANCE.md) for subjects and limits.

## 0.16.1 — 2026-11-03

### Highlights

- File names such as `test.pdf` no longer add a testing requirement just because they contain a word like `test`. An explicit request such as “run `test_*.py`” still applies.
- Marketplace metadata now includes the Skill's Apache-2.0 license and the packaged interface logo.

### Changes

- Session cleanup remains disabled. Ending a session saves its state, and `cleanup` exits with code 2 without deleting data. Existing sessions remain on disk and may use more storage. This version has no automatic retention cap or supported manual cleanup tool. See the [cleanup follow-up](docs/RETENTION_CLEANUP_FOLLOWUP.md).
- The historical-incident checker can execute its required tests as a release gate. Missing results, skipped tests and incomplete required test lists prevent a pass.
- Windows CLI acceptance checks the complete Job cleanup record. The Python dependency lock now uses the plugin's version.

### Validation

- A macOS source suite ran 2,899 tests with no failures or errors and 92 skips. Later focused acceptance-tool and Windows cleanup tests also passed. The earlier macOS and Windows portable-install result belongs to candidate `b18fd91`.
- The recorded macOS performance comparison met its declared budgets. The full historical Windows W1/W2 comparison remained unfinished. See [local acceptance](docs/LOCAL_ACCEPTANCE.md) and the [release assets](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.16.1) for the separate evidence.

## 0.16.0 — 2026-11-01

### Highlights

- **More credential formats are masked.** Context Guard masks documented credentials in the evidence it produces, diagnostics, and exports. This includes authorization headers and credentials in URLs. Shareable exports also remove paths to the data root, plugin root, Codex home, and operating-system home. See the [privacy guide](docs/PRIVACY.md) for the credential formats covered.
- **Export to a new file.** If a file already exists at the destination, Context Guard leaves it intact and reports an error. The project directory keeps its permissions.
- **Private records require verified access permissions.** Context Guard stops the write if it cannot confirm the permissions on the private file or directory.

### Changes

- **Use Codex's marketplace commands to install 0.16.0.** This version uses the experimental entry `context-guard@codex-context-guard-v016`. Finish tasks that need the old plugin before switching. Keep the old data and caches, and disable the old entry in the Plugins UI before trusting the new Hooks. The [original release notes](docs/releases/v0.16.0.md) describe the installation and rollback limits.
- **Session cleanup is disabled in this release.** Ending a session still saves its state and, when enabled, recovery information. Automatic cleanup does not run, and the `cleanup` command exits with code 2 without deleting anything. Existing sessions remain on disk and storage can grow. There is no automatic 30-day deletion, storage limit, or supported manual cleanup tool in 0.16.0.
- Session IDs are checked and encoded separately, so names such as `a/b` and `a_b` no longer collapse into one directory. Missing or invalid IDs are rejected. Direct commands use the selected `CODEX_HOME` for their default data root. Existing data stays on disk. The old directories created by collapsing IDs with underscores are no longer used for lookup.
- Repeated user-input events remain separate, including a pause followed by a resume and another pause in the same turn. Duplicate-shaped events are also noted in text-free diagnostics that do not decide authorization or completion.
- A request to read a file no longer gains an extra UI check just because its path contains `window` or `browser`. A request to inspect a real window or browser still requires UI evidence. Long requests retain the correct file-readback target even when it falls beyond the diagnostic excerpt.
- On Windows, Hook startup no longer depends on the `New-TemporaryFile` command when an interpreter is configured. Python discovery also avoids unnecessary PowerShell module loading for ordinary local PATH entries.
- **Known limitation in 0.16.0:** words such as `test` in a file path can still be counted as extra acceptance items. Several such misclassifications can activate Context Guard earlier than intended.
- Public-tree audits accept an optional private identity list outside the audited tree and match identities at semantic boundaries, without embedding them in distributed source. If a specified list is missing, unreadable, or inside the audited tree, the audit rejects it. The existing `--forbid` substring matching is unchanged.
- Schema 13, Stop protocol 5.0.0, the nine Hook events, and the default path for ordinary tools remain unchanged.

### Validation

- An isolated installation run on macOS and Windows passed eight checks and cleanup on the earlier `67985d7` candidate. It checked preservation of sample caches. The [acceptance record](docs/LOCAL_ACCEPTANCE.md) distinguishes that run from the final release and documents which Windows permission and daily-use cases were checked.
- The [original detailed 0.16.0 entry](https://github.com/GreenLv/codex-context-guard/blob/v0.16.0/CHANGELOG.md#L7) retains the earlier implementation and test details.

## 0.15.1 — 2026-10-05

### Highlights

- “Please continue” can lift an ordinary pause while preserving unfinished work. A later pause request takes effect again; replaying the same event does not create another change.
- A `sessions-v2` status query checks its sources before and after preparing the result. If a session resumes or its state changes during the read, the query does not present an outdated command or falsely report that nothing changed. The query does not write private state.
- The CLI and PostToolUse accept the same documented diagnostic options. A diagnostic command's failure is not treated as evidence that the requested work succeeded.
- Windows can publish state while a diagnostic reader is open when the system and filesystem support the required atomic rename. Unsupported systems report failure without a fallback.

### Changes

- A general resume does not satisfy a request for a specific input, exact marker, choice or external result. Those waits keep their own conditions.
- `checkpoint-status` checks its documented options consistently and rejects missing, repeated, abbreviated, unknown or incompatible arguments.
- Before changing the plugin selected in a HOME, finish old tasks or keep them in a separate HOME with their original runtime. Existing session state is not migrated.

### Validation

- The release source suite ran 2,389 tests with no failures or errors and 28 platform or capability skips. Bounded native macOS and Windows host checks passed their ten incident-profile gates.
- Historical coverage distinguishes passing source cases, cross-product analogues and an approved incomplete exclusion. Some historical native evidence remains missing. The Windows result review used saved captures rather than a new raw collection. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.15.0 — 2026-10-02

### Highlights

- New sessions use a lock that keeps another process from taking over a slow or paused state writer. Cleanup uses the same lock.
- Stateful Hooks start faster by loading their core in the router process. Ordinary tool calls keep their approval-free path.
- The always-loaded instructions are shorter. Advanced controls remain available through `checkpoint-status --commands`.

### Changes

- Looking up a missing session no longer creates an old-format directory that could cause its first Hook to be rejected.
- Before switching the plugin selected in a HOME, finish tasks that need the old version or keep them in a separate HOME. This version does not migrate or clean old session data.

### Validation

- In a declared macOS comparison, a fixed 100-event lifecycle took a median 11.81 seconds, down from 19.03 seconds. All 440 samples passed the semantic checks; this is a bounded benchmark, not a universal speed guarantee.
- macOS and Windows passed the recorded native Stop, compaction and recovery checks. Windows also tested old and new tasks in separate HOMEs. Detailed source, performance and historical-coverage results are in [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.14.3 — 2026-09-29

### Highlights

- Completion checks in long sessions are faster. In the recorded macOS incident-shaped fixture, median full-Hook time fell from 7.252 seconds in 0.14.2 to 0.472 seconds. The Windows test measured 0.489 seconds.
- If source records change while a completion decision is being checked, the current event's business-state changes are rolled back.
- An answered Chinese “why” question no longer returns as unfinished work when the question has a clear, supported scope. A mixed request such as “explain why the module failed, then fix it” still keeps the repair open.

### Changes

- Before saving a decision, Context Guard checks that the source records it used still match. It does not keep the processing cache across events.
- This release keeps schema 13, Stop 5.0.0 and all nine Hooks. When upgrading, preserve the cache used by running tasks and start a new task to load the new version.

### Validation

- The behavior suite ran 2,036 tests with no failures or errors and 22 platform or capability skips. Historical coverage included 37 directly passing active cases and 15 DSH-origin cases checked only as shared-semantics analogues.
- macOS and Windows isolated installation and bounded real-host checks passed. The synthetic host scenario did not reproduce every state of the original incident. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.14.2 — 2026-09-25

### Highlights

- A file or directory name no longer changes the meaning of an instruction. For example, renaming a test directory to `audit` or `commit` does not cancel a request to keep working.
- Recovery distinguishes a completed edit from work that is still outstanding. An edit followed by the requested readback is not treated as a request to edit the file again.
- An answer to a side question can be delivered while the original task and any unanswered question remain open.

### Changes

- If a user asks to wait for an exact phrase, only a later user message matching that phrase releases the wait. A general “continue”, a quoted phrase or a different case does not.
- Recovery retains restrictions, waits and proof first when its display budget is limited. A session-specific command can retrieve omitted entries.
- An optional transcript reader and independent answer review help associate answers with questions. Missing, changed or ambiguous source material remains unresolved; observing a message alone does not complete a task.
- The offline acceptance preflight checks the initial commit, session reuse, input digest and timeout budget before running a model.

### Validation

- Scoped macOS and Windows native replays covered complete answers, partial answers and exact-phrase waits. The partial-answer runs intentionally did not run the requested tests; the recorded future observation remained pending. Whole-task closure and actual compaction-threshold calibration were not established by these controls.
- Three original Windows cases remained unresolved at release: compaction and continuation, Stop feedback, and Archive-045. The release proceeded with these cases open, not as passed. See [development status](https://github.com/GreenLv/codex-context-guard/blob/e25be98037b2e1a9b3953faf6f3a1d45699407f6/docs/DEVELOPMENT_0.14.2.md) and [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.14.1 — 2026-09-22

### Highlights

- The plugin now supplies a terms-of-use link to the existing Apache-2.0 license in its marketplace metadata. If you already use 0.14.0, this change requires no configuration or task-data changes.

### Validation

- The isolated macOS install passed, and the [HOL scan](https://github.com/GreenLv/codex-context-guard/actions/runs/35697432313) cleared the missing terms-link finding. See the [original release notes](docs/releases/v0.14.1.md) for CI, Windows portable installation and registry status at release.

## 0.14.0 — 2026-09-21

### Highlights

- Finishing a repair can include a note that its long-term benefit still needs observation. That future observation no longer makes the completed repair look unfinished. A test or evaluation explicitly required now remains open until addressed.
- A short “continue” resumes the current task without becoming an unlimited request to keep working.
- A mixed request can receive its explanation while a requested file edit or other unfinished work stays open.

### Changes

- A general resume can lift an ordinary pause but does not replace a specifically requested input or confirmation.
- File names and URLs containing image-related words no longer create a visual-inspection requirement. Actual images and explicit visual questions still require the appropriate evidence.
- A request to run and report a test can be fulfilled by reporting its real failed result. A request that the test pass still requires a passing result.
- A supported single-file edit can be checked by independently reading the result, without first reading the old contents. Missing or conflicting evidence remains unresolved.
- Commit and push results are checked against the appropriate repository and remote. Normal tools continue to run under the host's permissions; explicitly adopted release and proof checks retain their rules.

### Validation

- Candidate `1217029` passed the recorded source matrix, candidate CI, HOL scan and five macOS portable gates. The final release had separate native, Windows, model and publication requirements. See [local acceptance](docs/LOCAL_ACCEPTANCE.md) for their subjects and outcomes.

## 0.13.9 - 2026-09-14

### Highlights

- Words such as `explicit` and `specific` no longer look like a CI dependency just because they contain “ci”. A real CI or external wait still needs its own result.
- An explanation no longer closes work that follows it. For example, “list the files, then delete temporary files” keeps the deletion pending. A supported question such as “how do I publish a version?” can close after the explanation without creating a publishing task.
- On Windows, the session-end Hook uses a faster Python startup path and fits the three-second Codex CLI limit in the recorded host checks.

### Changes

- A matching user confirmation can release its wait even before the task is parked. Ambiguous waits and external dependencies keep their own conditions.
- The managed installer recognizes an older staging directory from the same managed installation. It still rejects unrelated directories and directories containing Git metadata.
- Unrecognized or incomplete information requests remain open instead of being closed as fully answered. The release also includes the unpublished 0.13.4 scanner and manual registry-refresh updates.

### Validation

- macOS and Windows each passed six recorded real-host gates for the 0.13.9 runtime, along with portable installation and cleanup. Earlier candidate results retain their original subjects. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.13.3 - 2026-09-11

### Highlights

- Ordinary commits and single-branch pushes can continue even if an active release contract's private state cannot be read, including follow-on work in another repository.
- When release mode is active, covered publication actions still require verified release state. Tasks already using 0.13.2 keep their original cached runtime.

### Changes

- Context Guard first determines whether an action is subject to release checks, then reads the corresponding private state. The mode, ticket format and host permissions do not change.
- The English and Chinese READMEs clarify protection levels, contract adoption and maintainer checks.

### Validation

- macOS source checks passed 1,079 behavior tests. Candidate `7e5212e` passed CI, HOL and separate portable checks on macOS and Windows. The 0.13.2 real-host results remain attached to that earlier version. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.13.2 - 2026-09-10

### Highlights

- Ordinary work no longer triggers Context Guard execution-approval prompts. For example, a request to edit, commit and push can continue after compaction without reconstructing an edit-history chain. Your instructions, repository rules and host permissions still apply.
- An answered question no longer returns after compaction merely because another wait remains. A promise to investigate, a delayed reply or a reply from a different source does not by itself answer the current question.
- Explicit release verification remains active if private state is damaged. Covered release actions still need the exact, unexpired one-time ticket. If an old session's release mode is unknown, recognizable publication actions are blocked while ordinary edits can continue.

### Changes

- Release verification is enabled by adopting a release contract or explicitly using `context-guard release`. Merely selecting a Skill or having a file present does not enable it.
- The release includes the installed but unpublished 0.13.0 and 0.13.1 changes. Existing caches and old state are preserved; start a new task to load 0.13.2. Private schemas 9, 10 and 11 can migrate to schema 12.
- GitHub Enterprise release targets now include the separator between the host and repository. An omitted `--repo` can use a verified GitHub origin.

### Validation

- macOS source checks ran 1,076 behavior tests with no failures or errors and 11 capability skips. The recorded macOS portable checks and native macOS and Windows result reviews are separate evidence.
- Windows review examined saved captures and their links; it did not recollect the original run. Earlier 0.13.1 observations retain their original version. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.12.4 - 2026-09-09

### Highlights

- Finishing a child task no longer makes the whole task look complete. Outstanding work still needs its own evidence.
- Follow-up instructions preserve the unfinished task and its limits. Phrases such as “retry after correcting the permission boundary” no longer look like requests to replace a requirement.
- Confirmations clear only the matching pause. “The model is ready” does not clear a separate wait for a file check.
- After compaction or resume, recovery lists current requirements first and makes their full text available, including the end of long requirements.
- Commit-and-push keeps to the authorized files. A later request to push the current candidate uses that verified commit instead of expecting another commit to be created.

### Changes

- “Commit owned.txt; leave other.txt unchanged” permits only `owned.txt`. Quoted instructions and files mentioned only for reading or testing do not expand that scope. If further fixes are authorized, the guard waits for verified edits before freezing the commit contents; later changes cannot silently replace them.
- Push checks use the verified commit and destination. An explicitly named Git SHA must match the current candidate; stale or mismatched commits remain blocked. Restoring older state preserves valid commit observations, and the Hook response and private decision record use the same authorization result.
- A real correction still updates the intended requirement. If its target is unclear, the guard asks which requirement to change and keeps the existing ones until then. A child-task stop can end a wait for that child, but does not prove its result passed.
- Private state moves to schema 11. Schemas 10 and 9 migrate; schemas 7/8 remain read-only. Migration does not invent missing wait evidence, and schema 11 cannot be written back as schema 10 with information lost. The unpublished 0.12.2 and 0.12.3 versions were used in isolated trials; their caches and evidence retain those original versions.
- Long recovery text can be read with `recovery-page --session-id …`; recovery supplies the command. Pages belong to the requested session, and old continuation positions are rejected when the applicable requirements change.
- Maintainers can replay checks for Hook trust, waits, recovery, commits, local pushes and cleanup. Complementary runs may be combined only when they use the same runtime and platform, with each run's identity preserved. Missing evidence remains pending; contradictory evidence fails. See the [behavior baseline](docs/BEHAVIOR_BASELINE_0_12_4.md) and [acceptance record](docs/LOCAL_ACCEPTANCE.md) for host-dependent cases.
- The nine Hook events, public protocol versions, and Python 3.10+ standard-library runtime are unchanged.

### Validation

The recorded runtime passed independent macOS and Windows installation and portable checks, plus six host-behavior checks on each platform. These results retain their original run identities. Final-commit CI, HOL scanning, and public tag/Release verification are recorded separately in the [acceptance record](docs/LOCAL_ACCEPTANCE.md).

## 0.12.1 - 2026-09-07

### Highlights

- A clear push request no longer triggers a redundant request to restate the remote and branch in the Skill guidance. The runtime already resolves a unique target; instructions now match that behavior.
- Ordinary tasks read a shorter Context Guard Skill; advanced proof and control instructions load only when needed.
- Completion guidance follows the current work unit and required descendants, preserving ancestor constraints without reopening historical work.
- Avoid rerunning public-contract, runtime, conformance, and installer test subsets when the selected current-behavior suite already covers them; keep standalone checks and independent native gates.

### Changes

- Align the Skill, authorization reference, architecture and bilingual README guidance: ask only for an unresolved, conflicting or changed push target; preserve separate force-push, deletion and release authorization.
- Preserve advanced evidence, release authorization, migration, privacy, and successor controls in explicitly routed references.
- Keep the Hook implementation, schema, and protocol versions unchanged. The packaged Skill bytes change, so this patch uses a new version and does not overwrite consumed 0.12.0 caches.

### Validation

- Four added synthetic regressions pass against the unchanged runtime: plain Chinese/English push requests, commit-and-push, unresolved destinations, and prevention of destination/action expansion. All 18 authorization UX tests pass.
- The [acceptance record](docs/LOCAL_ACCEPTANCE.md) defines separate requirements for source checks, isolated installation, native acceptance, CI, and publication. Unchanged 0.12.0 host-behavior and performance results keep their original identities; the changed 0.12.1 runtime tree requires fresh install/parity evidence. Normal user-runtime upgrades remain separate.

## 0.12.0 - 2026-09-06

### Highlights

- Ordinary successful tool calls and safe endings no longer show routine Hook status messages. Errors and rejected actions remain visible.
- Release checks inspect what a supported command actually does. For example, printing `git tag v1.2.3` or running `npm publish --dry-run` is treated differently from creating a tag or publishing a package.
- Authorization follows the chosen profile. In this release, `standard` checks the user's authorization for covered high-risk actions, `release` also requires its adopted readiness contract and one-time ticket, and `observe` records the decision. Authorization does not extend to another repository or tag.
- Completed work is separated from the current work unit. Waiting or deferring can end a turn without presenting old unresolved work as current work.

### Changes

- Schema 10 adds work-unit states for active, completed, waiting, deferred and historical unresolved work. Schema 9 is a migration source; schema 7 and 8 remain read-only inputs.
- A unique successful result can be bound automatically when the current work unit is verifiably complete. Visual facts and ambiguous evidence continue to use explicit proof controls.
- Existing schema-9 sessions migrate on the actual resume path. If the task to resume is ambiguous, Context Guard asks for a selection rather than guessing.
- A release instruction is bound to the stated action, repository and target. Separate actions in the same instruction retain separate authorizations.

### Validation

- Source regression, performance, isolated installation and macOS and Windows native checks are documented separately in [local acceptance](docs/LOCAL_ACCEPTANCE.md). The release commit's CI and HOL, tag and GitHub Release were independently read back. Normal daily installation was a separate step.

## 0.11.1 - Unreleased

### Highlights

- This unpublished candidate lets release approval accept a compatible `release-readiness/v3` result while retaining support for `v2`. Unknown versions are rejected.
- Its installer can migrate the old fixed-name `codex-context-guard.marketplace` staging registration when the repository identity matches.

### Changes

- The readiness producer and `action-ticket/v1` consumer use a shared compatibility record for the supported `v2` and `v3` receipts. Other directories and repositories are not accepted for migration.

### Validation

- Focused candidate tests covered the old registration, the `v2` and `v3` ticket paths, and refusal of an unknown `v4`. Full source and native candidate acceptance remained required before publication.

## 0.11.0 - 2026-09-03

### Highlights

- Covered release actions require user authorization for the exact repository, commit, release identity and tool input before they run. Authorization for one candidate cannot be reused for another.
- Saying “wait” or “defer” does not hide work that is still authorized and ready. Quoted examples and reply annotations do not change the user's requirements.
- Completing one part of a task does not automatically close unrelated work. Large task status is kept short unless a full audit view is requested.

### Changes

- Schema 9 introduces `work-unit/v1`, and the execution protocol adds `action-ticket/v1`. The Hook set adds `PreToolUse`, for nine events in total.
- Command checks recognize supported shell and PowerShell wrappers, quoting and Windows path forms.

### Validation

- Runtime baseline `ea73bed` passed 412 source tests and the recorded isolated installation and Hook checks on macOS and Windows. Windows evidence was reported from the authorized remote host rather than a locally signed annex.
- The release commit passed main CI and HOL; the tag and bilingual GitHub Release were read back separately. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.10.0 - 2026-09-03

### Highlights

- Saying “physical identity verification is not needed”, or quoting that phrase, no longer creates a verification requirement. A direct request to verify a file or directory's physical identity still requires matching evidence.
- Evidence must prove the operation the user actually requested. A successful read cannot stand in for a requested write, and proof for one concrete operation cannot close another.
- If Context Guard cannot determine the requested operation, it keeps the item pending instead of dropping it. `clear-pending` clears only those unresolved operation guesses; it does not delete requirements or evidence.

### Changes

- Schema 8 derives the enforced `(operation, subjectId, requestedSurface)` contract from non-negated clauses. Evidence records carry the adapter-manifest version, and proofs fail closed when the concrete operation or manifest does not match.
- Schema 7 remains a read-only compatible input and upgrades deterministically with fresh private control state. Existing prompt, compaction, resume, fork, subagent, supersession, and evidence-replay ordering is unchanged.

### Validation

- The exact candidate passed the complete local source suite and the 12-job Ubuntu, macOS, and Windows CI matrix. Exact identities and counts are recorded in the [local acceptance record](docs/LOCAL_ACCEPTANCE.md).
- macOS and Windows independently passed native installation, repeat/no-op, byte-parity, self-test, and lifecycle checks for the same runtime tree. Context Guard ships from the source tag rather than a separate package artifact; publication readback remains a separate check.

## How protection evolved

These summaries describe each release line at the time. Later versions may change its installation or behavior.

- **0.17.x — manage older state and cleanup:** 0.17.0 restores optional session cleanup; 0.17.1 adds a tool to copy supported session state to the stable entry.
- **0.16.x — protect private data:** 0.16.0 expands redaction and export protection while suspending session deletion; 0.16.1 fixes path-based test misclassification.
- **0.15.x — preserve active sessions:** state writes use an exclusive lock, and pause and resume handling keeps unfinished work.
- **0.14.x — retain the right work across interruptions:** completed explanations, unfinished edits, waits and recovery evidence are handled separately.
- **0.13.x — let ordinary work continue:** ordinary tools no longer need a separate Context Guard execution approval, while explicitly adopted release checks remain available.
- **0.12.x — keep normal work quieter:** successful Hooks and safe endings become silent, with current and historical work tracked separately.
- **0.11.x — require authority before high-risk release actions:** covered publication mutations need a one-shot ticket bound to the exact candidate, while ordinary remote mutations need a current root-user instruction naming the action and target. Stop dispositions, quoted corrections, and cleanup-to-product scope changes are checked independently.
- **0.10.x — require evidence for the requested operation:** proof for a read, write, UI action, or public readback closes only that operation on the bound subject; ambiguous operations remain pending.
- **0.9.x — require complete, current evidence before finishing:** 0.9.4 makes a verified full-coverage checkpoint the only completion authority and preserves non-ASCII Hook input. 0.9.5 prepares routine file and text evidence automatically, narrows UI wording detection, and rejects evidence tied to the wrong task or path.
- **0.8.x — separate what user instructions, Skills, and the model plan may decide:** the user defines the task and write authority; adopted `AGENTS.md` or Skills define the workflow; Codex Plan is a revisable execution arrangement; and tool, file, image, or public-readback results provide factual evidence. Version 0.8.3 records these sources and an optional plan binding, requests review after drift, and does not turn them into new authority or tool interception.
- **0.7.x — bind evidence to the thing being verified:** check that evidence belongs to the required item, file or page, and complete requested scope. This line also added privacy-preserving protection for images and other multimodal inputs. It stores hashes and bounded metadata, and an image-editing task requires inspection of the changed image rather than only a successful tool call.
- **0.6.x — separate “the task is complete” from “this turn may stop”:** only a verified completion checkpoint marks the task complete. Waiting for the user, waiting for an external result, or explicitly deferring work can end the current turn while requirements remain open. `0.6.0` introduced this line but was never released; `0.6.1` was the first published version in the line.
- **0.5.x — explain stop decisions and make upgrades recoverable:** show why Context Guard allowed or stopped a response, and preserve immutable installed Hook versions so a damaged cache can be repaired safely.
- **0.4.x — remember the user's task:** preserve prompts, requirements, corrections, delegated work, and open acceptance items across compaction and resume; do not report the whole task complete while requested work remains.

## 0.9.5 - 2026-09-01

### Highlights

- For ordinary file and text results, Context Guard can prepare the proof record during a checkpoint. The agent no longer needs to write separate proof JSON for each such result.
- Mentions of a list or visible text no longer trigger an unrelated UI check. An explicit request to inspect or operate a UI still requires it.
- File and task evidence must come from reading the requested target. Opening a UI or echoing a path alone is not enough.

### Changes

- Image inspection, UI readback and cases that cannot be checked exactly still use the explicit `register-proof` path. A failed checkpoint does not leave a partial proof.
- Rejection messages identify the expected result and where the available evidence does not match.

### Validation

- macOS and Windows separately passed the recorded source, isolated-install and fresh trusted-Hook checks. The macOS record also includes daily managed installation. CI, public release readback and downstream adoption are separate evidence; see [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.9.4 - 2026-08-28

### Highlights

- Hooks read input as UTF-8, preserving Chinese and other non-ASCII text in recorded prompts and replies. Invalid bytes are rejected visibly.
- A task can be marked complete only when a verified checkpoint covers its requirements. Unresolved waits remain protected.
- A standard-library incident library and reviewed public test cases make protocol regressions reproducible.

### Changes

- `Stop` and `UserPromptSubmit` decode their input independently of the host's locale. Existing Hook events, saved-state format and Python support are unchanged.
- The incident-library tool can ingest, validate, summarize and export reviewed public fixtures. CI does not read the private library.

### Validation

- macOS and Windows each passed the recorded source, installation and fresh-Hook checks, including 233 source tests. Platform skips and the separate CI and release results are in [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.12 - 2026-08-27

### Highlights

- Discussing a completion phrase as a category, such as “`任务已完成` 类声明”, no longer looks like a claim that the current task is complete. A direct completion claim still receives the usual check.

### Changes

- The classifier recognizes this bounded Chinese wording without weakening all handling of quoted completion statements. Existing installed 0.8.11 caches remain unchanged.

### Validation

- Focused regressions passed, and the macOS suite ran 219 tests with five capability skips. The recorded candidate passed managed installation and fresh trusted-Hook tasks on macOS and Windows. CI and release evidence are separate; see [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.11 - 2026-08-27

### Highlights

- When Codex removes an old plugin cache, an open task first tries its original Hook directory and can fall back to the newest valid managed version.
- Clearly redacted values and short readable token examples no longer trigger a private-token leak warning. Values that look like real control tokens remain blocked.
- If historical caches are missing, the installer explains how to restore them.

### Changes

- A fallback directory must have a valid `X.Y.Z` name and cannot be a symbolic link. The fallback may use a newer runtime than the one originally trusted; exact old-version restoration still requires a trusted archive.

### Validation

- macOS and Windows passed the recorded checks and fresh interactive Hook trust. macOS reproduced host cache removal and restored indexed versions; the Windows fresh task did not remove its old caches. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.8 - 2026-08-25

### Highlights

- Hooks choose an available Python 3.10 or newer instead of blindly using the first `python3` or `python` on PATH. On macOS, this avoids selecting the unsupported system Python 3.9 when a supported version is available later on PATH.
- If no supported interpreter can be found, the Hook stops and reports what is needed.

### Changes

- POSIX and Windows use launchers that check Python versions before starting the Hook. The existing Hook protocol and private state behavior stay the same.

### Validation

- The earlier 0.8.7 macOS installation passed its checks but a newly trusted Hook failed when the host selected Python 3.9. A fresh trusted task using 0.8.8 ran the affected Hooks without that failure.
- The recorded macOS and Windows checks include isolated installation and fresh Hook trust; their exact candidates and platform scope are in [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.7 - 2026-08-25

### Highlights

- Upgrading preserves old plugin-cache files that are outside the trusted product archive, including a `.pyc` retained as evidence, even if Codex replaces the cache directory.
- Those extra files are backed up and restored separately. They do not become trusted product files.

### Changes

- The installer compares historical caches with their archives before upgrading and saves any extra files that need to survive. It removes the backup only after restoration is verified.
- If the upgrade is interrupted, the next managed `--apply` attempts recovery before continuing. Read-only inspection reports the incomplete state without changing it.

### Validation

- A macOS 0.8.6-to-0.8.7 isolated upgrade preserved the previously retained `.pyc` and historical cache snapshot. Windows acceptance also preserved the recorded older cache snapshots. The 0.8.5 `.pyc` already lost during the previous upgrade was not recreated. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.6 - 2026-08-25

### Highlights

- The installed-plugin lifecycle check no longer creates `__pycache__` or `.pyc` files inside the plugin directory when its caller has not set `PYTHONDONTWRITEBYTECODE`.

### Changes

- The check temporarily disables bytecode writes while importing the installed runtime, then restores the caller's setting. Hook subprocesses keep their existing behavior.

### Validation

- On Windows, the previous 0.8.5 check produced a `.pyc` in the cache, so final acceptance failed. The 0.8.6 macOS check passed without creating bytecode.
- A later Windows 0.8.6 upgrade lost that retained 0.8.5 `.pyc` when the cache was replaced. Version 0.8.7 addressed this separate preservation issue. The platform results and remaining limits are in [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.5 - 2026-08-25

### Highlights

- A downstream installation pinned to a specific commit can upgrade even when its existing marketplace registration points to the previous checkout or its staging copy.

### Changes

- Migration accepts only the managed Context Guard roots under `CODEX_HOME/upstreams/context-guard` whose manifest names this repository. Other paths remain rejected.
- A read-only check reports when `--apply` is needed without changing the installation or private task data.

### Validation

- An isolated pinned installation upgraded from 0.8.3 to 0.8.5, retained its older cache and archive, and passed its recorded installation checks. Daily-home migration and public release checks are separate evidence. See [local acceptance](docs/LOCAL_ACCEPTANCE.md).

## 0.8.4 - 2026-08-25

### Highlights

- Marketplace registration now uses a cleaned staging copy of the source. Codex can refresh the plugin cache without copying the checkout's `.git` directory into it.
- An existing checkout-based registration can migrate with the managed `--apply` operation. That operation also repairs an affected cache from its trusted archive.

### Changes

- Read-only checks report when migration or repair is needed without changing the installation. Staging rejects embedded Git metadata and removes temporary directories after success or failure.
- Historical plugin versions and private task data are preserved.

### Validation

- Windows real-CLI tests covered registration, migration, cache repair and a second no-op run. macOS source and isolated-install checks also passed. CI, tag and release results are recorded separately in [local acceptance](docs/LOCAL_ACCEPTANCE.md).

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

## 0.5.0 - 2026-08-09 — installed version, not separately released

### Added

- `context-guard diagnose` explains the latest stop decision with bounded, privacy-preserving records instead of requiring maintainers to infer it from raw task text.
- Installed Hook versions are archived with hashes so older tasks can keep using their original runtime and damaged live caches can be repaired from a trusted copy.

## 0.4.16 - 2026-08-09 — installed version, not separately released

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
