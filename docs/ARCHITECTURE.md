# Architecture

Context Guard is a correctness sidecar for Codex. It observes lifecycle events,
maintains private local task state, compiles a bounded recovery packet, and
gates completion claims against successful evidence. It does not replace or
control Codex-native orchestration.

## Responsibility boundary

| Concern | Codex owns | Context Guard owns | Context Guard does not do |
| --- | --- | --- | --- |
| Conversation | transcript and compaction | pre-compact correctness snapshot and bounded recovery | copy the full transcript or rewrite the compact prompt |
| Planning | Plan mode and `update_plan` lifecycle | latest successful plan mirror as a read-only index | maintain a second editable plan |
| Goals | Goal lifecycle and UI | completion evidence for guarded task requirements | create, pause, or modify Goals |
| Memory | cross-task recall | task-local authoritative ledger | treat memory as requirement authority |
| Agents | spawning, messaging, waiting, permissions | delegated provenance and bounded result envelope | implement a scheduler, mailbox, or task lock |
| Worktrees | isolated file changes and Git state | bounded artifact/command evidence | synchronize or merge worktrees |
| Hooks | lifecycle event execution and trust | local state and completion policy | claim Hooks are a complete security boundary |

## End-to-end lifecycle

```mermaid
sequenceDiagram
    actor User
    participant Codex as Codex native runtime
    participant Hooks as Context Guard Hooks
    participant Ledger as Private ledger (PLUGIN_DATA)

    User->>Codex: Requirements, constraints, and revisions
    Codex->>Hooks: UserPromptSubmit
    Hooks->>Ledger: Journal prompt and update stable requirement IDs

    Codex->>Hooks: PostToolUse
    Hooks->>Ledger: Record evidence or authorize a verified private stage request

    Codex->>Hooks: PreCompact
    Hooks->>Ledger: Verify integrity and write recovery snapshot
    Codex->>Codex: Native context compaction
    Codex->>Hooks: SessionStart (compact or resume)
    Hooks-->>Codex: Bounded recovery packet as additional context

    Codex->>Hooks: Stop at the turn boundary
    Hooks->>Ledger: Resolve integrity, checkpoint, completion, continue, persistence, wait, then default yield
    alt Verified checkpoint
        Hooks-->>Codex: Derive complete and allow normal completion
    else Bounded continuation trigger
        Hooks-->>Codex: Continue at most twice or report the blocker
    else Wait, deferred, or default yield
        Hooks-->>Codex: Yield with pending requirements preserved
    end
```

The arrows describe lifecycle observation and bounded context injection. Codex,
not Context Guard, performs compaction, controls the task lifecycle, and runs
tools or subagents. The private ledger never becomes a second transcript or
editable plan.

## Four-layer model

### L1: immutable task contract

Each prompt is stored in a private, immutable record with a content hash.
Metadata in the session state points to those records. Root human prompts can
create requirements, acceptance items, revisions, and control actions.
Delegated prompts are journaled with delegated authority and cannot create,
cancel, or supersede root requirements.

Supersession is append-only. A later instruction records which earlier item it
replaces; it does not rewrite the earlier record. Negated or ambiguous
supersession language fails closed and leaves the existing requirement active.

### L2: bounded work state and evidence

The latest successful native `update_plan` call is mirrored into
`work_state.plan_snapshot`. Failed plan updates do not replace the last usable
snapshot. The mirror is recovery context only and never controls Codex Plan
mode.

Post-tool evidence records bounded input/output summaries, actor provenance,
outcome, and outcome basis. Structured success/failure is preferred.
Unstructured text and weak success markers are unknown. An exact standalone
completion marker can be successful only when the verification command itself
fails on unmet checks.

Binary and data-URL values are replaced with type, length, and SHA-256 metadata.
Generic typed text remains text; binary omission is based on field and container
semantics rather than a broad base64-looking heuristic.

### L3: delegated-agent provenance

`SubagentStart` records a bounded delegated contract and injects the root
authority boundary. `SubagentStop` stores a bounded result summary and checks for
the result envelope fields `Outcome`, `Evidence`, `Validation`, `Limitations`,
and `Next`.

The plugin does not read or copy the delegated agent transcript or hidden
reasoning. A delegation wrapper is accepted as delegated only when runtime
metadata or a currently running agent corroborates it.

### L4: recovery and completion verification

`PreCompact` validates state integrity, saves an atomic recovery snapshot, and
fails closed when the correctness state cannot be trusted. `SessionStart` on
compact/resume restores a bounded packet in this priority order:

1. active requirements and acceptance items;
2. explicit supersessions;
3. latest native-plan mirror;
4. active and recent bounded agent state;
5. recent successful/failed evidence;
6. completion rules.

The completion gate is bound to the current turn. Only successful evidence
already captured by the Hook may satisfy a requirement or acceptance item.
Private staging remains in plugin data and is never appended to the visible
assistant response.

Schema 5 gives each active completion attempt one `staged_control` slot. It is
either a verified checkpoint or one typed non-completion disposition:
`continue`, `user_wait`, `external_wait`, or `deferred`. `complete` is not a
disposition; it can be derived only when Stop validates and consumes a
checkpoint covering every non-superseded requirement and acceptance item.
Staging the same control is idempotent, a different control conflicts, and an
intentional change requires `--replace`.

The private `stage-checkpoint` and `stage-disposition` CLI commands are
prechecks, not state-writing authorities. `PostToolUse` is the authoritative
staging path: it verifies the exact command, expected data directory, session,
turn, token hash, output marker, and successful exit status before storing the
single control. A request observed only in assistant text, tool input, or an
unsuccessful/unmatched tool result cannot stage anything.

Stop protocol 1.0.0 applies this fixed priority:

1. private-state or prompt-boundary integrity failure, leaked private
   checkpoint/disposition metadata, and malformed staged control fail closed;
2. a hash-verified staged checkpoint is validated first; a valid checkpoint is
   consumed as `complete`, while an invalid checkpoint blocks;
3. a high-confidence whole-task completion claim without a valid checkpoint
   blocks even if a wait or deferred disposition was staged;
4. staged `continue` requests bounded continuation;
5. explicit user persistence blocks a terminal yield unless the next priority
   establishes a genuine unavailable boundary;
6. `user_wait` and `external_wait` yield with requirements still pending;
   `deferred` also yields when persistence is absent, or when the hash-verified
   prompt denies or excludes the specific action identified as deferred; and
7. with no staged control and no earlier trigger, Stop yields safely and leaves
   every unresolved requirement pending.

Continuation is capped at two correction turns. Classifier 2.0.0 records the
observed natural-language outcome, action facts, and anomalies for diagnosis;
inferred action ownership no longer drives ordinary continuation. Only the
narrow high-confidence whole-task-completion and explicit-persistence checks
participate in the fixed priority above. Classification reads the full
hash-verified prompt record; an ambiguous prompt boundary fails closed.

## Hook lifecycle

| Event | Purpose | Visible context |
| --- | --- | --- |
| `UserPromptSubmit` | journal prompt, classify authority, update requirements and revisions | activation/status and bounded completion instructions |
| `PostToolUse` | record bounded evidence, observe successful `update_plan`, and authoritatively stage a verified private control request | none |
| `PreCompact` | validate state and write recovery snapshot | continue/fail-closed result |
| `SessionStart` | restore bounded context on compact/resume | recovery packet |
| `SubagentStart` | record delegated lifecycle and inject contract | bounded delegated contract |
| `SubagentStop` | record bounded result envelope | warnings only when needed |
| `Stop` | apply the fixed integrity/checkpoint/completion/continue/persistence/wait/default-yield priority | continuation only when required |
| `SessionEnd` | mark session ended, write final recovery, run retention cleanup | none |

## Private state

Schema 5 contains:

- session identity and lifecycle timestamps;
- prompt metadata and immutable prompt records;
- requirements, acceptance items, and supersessions;
- evidence with monotonic IDs and bounded retention;
- `work_state.plan_snapshot`;
- bounded agent records;
- compaction history;
- one turn-bound completion attempt with protocol version, token hash, staging
  timestamp, and a single checkpoint-or-disposition `staged_control`;
- a checkpoint-derived completion record;
- at most 32 hash-only Stop decision records with protocol/classifier versions,
  decision source, disposition and outcome enums, bounded reason/action enums,
  prompt/reply SHA-256, and no raw reply text;
- integrity status and a canonical content hash.

Writes are atomic. Session operations use a cross-platform lock. State is
validated before use; corrupted state is preserved for diagnosis and rebuilt
only from hash-verified prompt records. Reconstructed requirements return to
pending because prior evidence cannot be silently re-trusted. Schema 1, 2, 3,
and 4 migrate to schema 5 while preserving the durable ledger. Migration
deliberately discards any in-flight completion attempt, token, or staged control
so a stale turn cannot authorize the new protocol.

## Historical Hook cache lifecycle

The installer archives immutable version trees under
`CODEX_HOME/plugins/cache-archive/codex-context-guard/context-guard/<version>`
and stores their SHA-256 manifests in an atomic trusted index. It archives live
versions before invoking Codex, restores deleted historical live caches after
installation, and archives the newly installed version after parity succeeds.
Read-only runs audit only; `--apply` repairs a live cache only from a valid
archive. Missing or corrupt archive evidence fails closed, and no archive is
auto-pruned.

## Exports and successor packs

`export` produces a redacted project-bounded handoff. `rollover` additionally
requires a user-prepared input, validates file paths and hashes, enforces byte
and file limits, and writes to a new non-overwriting directory. Neither action
creates, activates, retires, or grants authority to a task.

## Maintenance boundary

Version 0.6.0 is limited to the schema-5 private turn-control protocol,
diagnostics, compatible cache lifecycle, correctness/security, tests, and
documentation. It does not add a Hook event, matcher, or Codex Hook payload
field; the existing eight-event `hooks.json` wire contract remains compatible.
Requirement-to-evidence semantic relevance is not implemented by 0.6.0. It
remains benchmark-first research and is deferred to a possible 0.7.0 capability
only after positive, negative, adversarial, multilingual, false-acceptance,
false-rejection, and abstention thresholds are approved. A shared multi-agent
workspace also requires separate evidence and approval.
