---
name: context-guard
description: Preserve authoritative task requirements, acceptance criteria, bounded native-plan state, delegated-agent results, and verified evidence across Codex context compaction. Use for long or complex tasks, Goal work, resumed sessions, subagent workflows, explicit context-guard controls, redacted or successor handoff exports, or whenever completion must be checked against an immutable local requirement ledger.
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
8. For progress, blocked, status, control, or clarification replies, do not stage
   a completion checkpoint.
9. Before ending an incomplete guarded turn, use the exact injected
   `stage-disposition` command only when one of these typed boundaries is true:
   - `continue`: authorized assistant work should continue now;
   - `user_wait`: the next required action belongs to the user;
   - `external_wait`: progress depends on an external actor or system;
   - `deferred`: the remaining action is explicitly denied or outside the
     current bounded scope.
   The command performs a read-only precheck; the `PostToolUse` Hook writes the
   authenticated, turn-bound control. A different staged control requires the
   explicit `--replace` flag. If no disposition is staged, Stop yields safely
   and every unverified item remains pending.
10. Before claiming full completion for an active guarded task:
   - Run the exact `checkpoint-status` command injected for the current turn.
   - Select only successful `E####` evidence printed by that command. Plain-text
     tool output without a structured success status or an exact authoritative
     completion marker is recorded as `unknown` and cannot close an item.
     For string-only shell tools, make the verification command fail on any
     unmet condition and print a final standalone `Script completed` or
     `Command completed` line only after every check passes. The marker is
     exact and must not have trailing punctuation.
   - Run the injected `stage-checkpoint` command with one
     `--requirement ID=E####[,E####]` flag for each pending requirement and one
     `--acceptance ID=E####[,E####]` flag for each pending acceptance item.
     The command performs a read-only precheck; the `PostToolUse` Hook commits
     the request to private plugin data outside the workspace sandbox.
   - If staging fails, continue working or report the task as incomplete.
11. Never stage both a completion checkpoint and an incomplete-turn disposition.
    `complete` is not a `stage-disposition` value; it is derived only from a
    validated private checkpoint.
12. After private staging succeeds, send a normal concise final response with no
    checkpoint or disposition footer. The Stop Hook validates the private
    turn-bound record.

Previously passed items carry their authenticated evidence forward. A new user
turn invalidates any unstaged or unused completion attempt from the prior turn.

## Codex-native boundaries

- Let Codex own Plan mode, `update_plan`, Goal mode, compaction, subagent
  orchestration, permissions, worktrees, transcripts, and memories.
- Treat the recovered plan as a read-only mirror of the latest observed
  `update_plan` call. Continue to update the native plan through Codex tools.
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
data, raw prompts, transcripts, credentials, tokens, or plugin caches. Export
only when the user explicitly requests it; exported handoffs are redacted by
default.
