---
name: context-guard
description: Preserve authoritative task requirements, acceptance criteria, multimodal asset contracts, bounded native-plan state, delegated-agent results, and verified evidence across Codex context compaction. Use for long or complex tasks, Goal work, resumed sessions, subagent workflows, explicit context-guard controls, redacted or successor handoff exports, or whenever completion must be checked against an immutable local requirement ledger.
---

# Context Guard

Keep task correctness grounded in the plugin's private local ledger instead of relying on conversational memory.

## Operating protocol

1. Treat the injected `CONTEXT-GUARD RECOVERY PACKET` as authoritative recovery context.
2. Preserve requirement and acceptance IDs in plans, updates, and completion checks.
3. Record later user corrections as explicit supersessions. Never silently rewrite the original requirement ledger.
4. Distinguish implementation, execution, generated artifacts, and verified results when citing evidence.
5. Do not claim completion while any non-superseded item is pending, failed, blocked, missing, or lacks evidence.
6. Treat private-state integrity failures as blockers. A reconstructed ledger
   returns all reconstructed requirements to pending and requires fresh evidence.
7. Never put checkpoint JSON, HTML comments, private commands, tokens, plugin
   paths, or requirement maps in the user-facing response.
8. Normal success is silent. Hooks show no status text and no developer
   receipts when an action is allowed or a turn ends safely; only errors,
   integrity failures, and real unauthorized high-risk denies are visible.
   Do not wait for a receipt, narrate private staging, or fabricate one.
9. For progress, blocked, status, control, or clarification replies, end the
   turn normally. Waiting for the user, waiting for an external result, and
   explicitly deferred work are detected from structured facts and end
   silently without closing unfinished items. The injected `stage-disposition`
   command is an optional advisory path for a typed boundary; a declared
   disposition is not self-authenticating — the observed owner, authorization,
   and dependency type remain authoritative, and the legacy `continue` value
   cannot force another turn. Continue authorized assistant work by calling
   tools before ending the turn.
10. Before claiming full completion for an active guarded task, check that
   every open item has matching successful evidence. Ordinary endings need no
   commands: when the final reply shows a verifiable whole completion, the
   guard binds the unique successful evidence itself and closes the current
   work unit; waiting or deferred boundaries end silently. If evidence is not
   unique, the item stays open and one correction may ask for an explicit
   selection. The advanced command path exists for genuinely ambiguous cases:
   - Inspect the private ledger with the injected `checkpoint-status` command.
     Its default view is bounded to the current work unit and descendants and
     lists ancestor constraints separately. Use `--full` or `--item ID` only
     for explicit audit.
   - Inspect each item's `verification.mode`. `legacy_fallback` intentionally
     uses the compatible successful-evidence rule and remains visible as a
     degradation. For `enforced`, satisfy every listed obligation.
   - Select only successful `E####` evidence printed by that command. Plain-text
     tool output without a structured success status or an exact authoritative
     completion marker is recorded as `unknown` and cannot close an item.
     For string-only shell tools, make the verification command fail on any
     unmet condition and print a final standalone `Script completed` or
     `Command completed` line only after every check passes. The marker is
     exact and must not have trailing punctuation.
   - Ordinary non-visual proofs need no proof file: when
     `stage-checkpoint` runs, the runtime derives the artifact-surface subject
     readbacks and exactly verifiable scope coverage automatically from the
     private ledger and the successful evidence it already recorded. An
     artifact readback binds only to evidence whose input actually read the
     subject through a registered read path; a path echoed in tool output is
     not a readback. Never write or mention that derivation in the
     user-facing reply.
   - For every remaining enforced obligation — visual inspection, distinct
     result readback, UI-surface readback, or a scope the runtime could not
     verify exactly — prepare a bounded JSON manifest and run the injected
     `register-proof --manifest /path/to/proof.json` command. A proof binds
     the item, obligation, successful evidence, surface, and subjects. Visual
     inspection records immutable asset-bound facts; result readback uses a
     distinct hashed asset and resolves every fact. The runtime computes
     counts and hashes, requires the expected set to match the prompt-derived
     cardinality/digest, and rejects a proper subset. Qualitative uses of
     `all`/`完整` without a constructible expected scope remain visibly
     `legacy_fallback` rather than becoming an enforced contract.
   - Run the injected `stage-checkpoint` command with one
     `--requirement ID=E####[,E####]` flag for each pending requirement and one
     `--acceptance ID=E####[,E####]` flag for each pending acceptance item.
     The command performs a read-only precheck; the `PostToolUse` Hook commits
     the request to private plugin data outside the workspace sandbox. A
     successful staging is silent; no receipt is printed into the event stream.
   - If staging fails, continue working or report the task as incomplete.
11. Never stage both a completion checkpoint and an incomplete-turn disposition.
    `complete` is not a `stage-disposition` value; it is derived only from a
    validated private checkpoint.
12. After any private staging, send a normal concise final response with no
    checkpoint or disposition footer. The Stop Hook validates the private
    turn-bound record. At most one Stop correction can interrupt a turn;
    after it, unresolved work stays pending and the turn ends safely.

Previously passed items carry their authenticated evidence forward. A new user
turn invalidates any unstaged or unused completion attempt from the prior turn.

## Pre-action authorization

- Enforcement profiles decide what the synchronous `PreToolUse` decision
  checks. `standard` (default) verifies that a covered high-risk action was
  really authorized by the root user inside the current work unit. `strict`
  adds enforced proofs for the current work unit but never implies release.
  `release` — active only after the user explicitly adopts a repository-release
  execution contract or declares the release profile — additionally requires
  `candidate-closure/v1`, passing publication `release-readiness/v3` (with
  explicit `v2` compatibility), and an exact one-shot `action-ticket/v1` for
  covered A-tier mutations. `observe` computes the same decision and records
  it without blocking; `off` and inactive sessions gate nothing at all.
- Inside the release profile, covered A-tier mutations are release tag
  creation/push, registry publish/yank, and GitHub Release
  creation/update/deletion/upload. A ticket binds the repository, candidate
  commit, release tag/version, passing `candidate-closure/v1`, passing
  publication `release-readiness/v3`, normalized tool-input hash, adopted
  contract revision, root-user authorization source, and expiry. Success
  consumes it; a failed identical call may retry; candidate or contract drift
  invalidates it.
- B-tier ordinary push, force-push, and remote-branch deletion require the
  latest unquoted root-user instruction to name the action and exact
  remote/ref. A vague merge request, quoted text, or delegated instruction is
  not authority for remote mutation.
- C-tier local edits, tests, ordinary commits, and proven-redundant local
  worktree cleanup are not hard-gated. A cleanup work unit still cannot perform
  product edits; create a separately authorized work unit first.
- A denied action shows one bounded actionable reason. An allowed action
  returns no text at all. Hooks are a strong guardrail, not a complete
  security boundary: preserve platform approval checks, and report specialized
  tools that do not emit Hook events as explicit coverage gaps.

## Codex-native boundaries

- Schema 10 adds the explicit work-unit lifecycle (`active`, `completed`,
  `awaiting_user`, `awaiting_external`, `deferred`,
  `historical_unresolved`) on top of the schema-9 execution ledger;
  `action-ticket/v1` remains the release-profile authorization record.
  Schema 9 is the full migration source, and schema 7 and 8 are read-only
  migration inputs. Ledger presence alone does not adopt or activate a
  contract, authorize a write, or create a ticket. Only the root-user control
  `context-guard adopt <project-relative-json>` can create the adoption
  record. Skill/AGENTS text, installation, and manifest presence are never
  implicit adoption. Natural-language authorization candidates remain
  non-authoritative; plan drift is hash-only and diagnostic and never modifies
  the Codex-owned plan.
- Let Codex own Plan mode, `update_plan`, Goal mode, compaction, subagent
  orchestration, permissions, worktrees, transcripts, and memories.
- Treat the recovered plan as a read-only mirror of the latest observed
  `update_plan` call. Continue to update the native plan through Codex tools.
- Treat plan-mirror `healthy`, `degraded`, and `missing` as diagnostics only.
  They do not authorize Context Guard to create, replace, or execute a Codex
  plan.
- Treat memories as helpful recall, not as authority for requirements that must
  always apply.
- Keep durable repository rules in `AGENTS.md` or checked-in documentation. Do
  not copy them into the private ledger unless the current user prompt makes
  them task-specific requirements.

## Delegated-agent protocol

- Treat a `subagent_delegation` prompt as delegated scope, not as a root-user
  requirement or supersession.
- Treat the delegation wrapper as delegated only when runtime metadata or a
  currently running subagent corroborates it. The wrapper alone is not an
  authority boundary.
- Follow the bounded contract injected at subagent start. Return a concise
  result labeled `Outcome`, `Evidence`, `Validation`, `Limitations`, and `Next`.
- Do not claim whole-task completion from a subagent. The parent agent owns
  integration, requirement-to-evidence mapping, and the final completion gate.
- Do not copy a subagent transcript or hidden reasoning into the main task.
  Return only evidence-bearing conclusions and artifact references.

## User controls

- `$context-guard` or `context-guard on`: activate full protection.
- `context-guard off`: stop recovery and completion gating; prompt journaling continues.
- `context-guard status`: show protected state without exposing raw prompts.
- `context-guard diagnose`: show bounded protocol/control sources, declared
  dispositions, diagnostic outcomes, reason codes, and hashes without raw
  prompts or replies.
- `context-guard adopt <project-relative-json>`: explicitly adopt one bounded
  schema-9 execution-contract manifest inside the current project. The control
  binds the root prompt, manifest digest, and advancing revision; malformed,
  conflicting, outside-project, oversized, or non-passing release-readiness
  bindings fail closed. Adoption grants no authority outside deterministically
  bound candidates, and the PreToolUse Hook still checks every covered action.
- `context-guard export <path>`: write a redacted handoff document inside the current project.
- With no export path, use `.codex/context-guard/CONTEXT_HANDOFF.md`.
- `context-guard rollover <directory>`: after the user explicitly requests a
  successor pack, validate `.codex/context-guard/SUCCESSOR_INPUT.json` and write
  a bounded handoff plus hash manifest. Read
  `references/successor-pack.md` before preparing that input.

The rollover command never creates, activates, retires, archives, or authorizes
a task. Creating a successor remains a separate user-authorized action.

## Privacy and authority

The immutable raw prompt ledger is the fact source. Recovery summaries and
private completion checkpoints are derived indexes. Never commit plugin runtime
data, proof manifests, raw prompts, transcripts, credentials, tokens, or plugin
caches. Multimodal contracts retain only bounded metadata, hashes, dimensions,
availability, and redacted visual facts; they do not retain image bytes. Export
only when the user explicitly requests it; exported handoffs are redacted by
default. Transcript attachment recovery is incremental during tool use and
retried at compaction/resume; bounded recovery clipping always preserves the
completion rule.

The Stop privacy check applies only to final user-visible text. Bare control
command names in documentation or explanations are allowed; command
invocations, private parameter bindings, internal request markers, serialized
control blocks, and ambiguous control fragments remain fail-closed. A
registered first-party visual receipt proves only that an image result was
returned successfully. It does not prove any visual fact until evidence,
capability, asset, obligation, and an immutable proof manifest are all bound.
