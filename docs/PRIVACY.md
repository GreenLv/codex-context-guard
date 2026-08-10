# Privacy and Data Handling

Context Guard deliberately separates public plugin code from private runtime
state.

## Where data is stored

When installed as a plugin, Codex supplies:

- `PLUGIN_ROOT`: the read-only installed plugin code and assets;
- `PLUGIN_DATA`: the writable private data directory for this plugin.

Context Guard writes session state, immutable prompt records, recovery files,
and private completion state only under `PLUGIN_DATA`. A direct-command fallback
under the user's Codex home exists for isolated development; production plugin
execution should use the Codex-provided data directory.

No plugin runtime state belongs in this Git repository.

## Data categories

The private store may contain:

- raw prompt bodies in immutable per-prompt files;
- session and turn identifiers;
- extracted requirements, acceptance items, and revisions;
- bounded tool input/output summaries and outcome metadata;
- the latest bounded native-plan mirror;
- bounded delegated-agent metadata and final result summaries;
- recovery snapshots and private completion checkpoints;
- a turn-bound protocol attempt containing a token hash and at most one staged
  checkpoint or typed disposition (`continue`, `user_wait`, `external_wait`, or
  `deferred`); and
- at most 32 recent Stop decisions containing timestamps, turn IDs,
  protocol/classifier versions, decision-source/disposition/outcome enums,
  bounded reason/action enums, and prompt/reply SHA-256.

The plugin intentionally does not store chain-of-thought or copy complete root
or delegated-agent transcripts.

## Minimization

- Evidence and recovery text are bounded.
- Binary/data-URL payloads are replaced by type, byte/character length, and
  SHA-256 metadata.
- Delegated-agent results are bounded summaries rather than transcripts.
- Recovery prioritizes active requirements and failures over historical detail.
- Disposition requests accept only a fixed disposition enum and derive a fixed
  reason enum; there is no free-form disposition reason field.
- Protocol and decision diagnostics retain hashes and bounded enums, never raw
  reply text, chain-of-thought, local paths, credentials, or plaintext private
  tokens. Recovery includes only the latest short fail-closed reason when
  relevant, not the decision history.
- Schema migration invalidates in-flight private tokens and staged controls
  instead of carrying turn authorization across protocol versions.
- Ended sessions become eligible for cleanup after 30 days.

## Redaction

Redacted handoff and successor exports remove or omit:

- raw prompt files and transcript bodies;
- common API keys, bearer credentials, passwords, and authorization headers;
- URL query values;
- private completion metadata and plugin-private paths;
- unrequested binary payloads.

Redaction is defense in depth, not a guarantee that arbitrary user text contains
no sensitive information. Review every export before sharing or committing it.

## Network behavior

The Hook runtime does not make network requests and has no third-party runtime
dependencies. Git operations, plugin installation, and GitHub publication are
outside the Hook runtime and remain explicit user actions.

## User controls

- `context-guard off` stops recovery and completion gating but keeps prompt
  journaling for the active task.
- `context-guard status` exposes counts and integrity state, not raw prompts.
- `context-guard diagnose` exposes bounded decision metadata and hashes, not
  raw prompts or replies.
- `stage-checkpoint` and `stage-disposition` preflight private turn-bound
  requests; their tokens, commands, markers, and stored controls must never be
  copied into a user-facing reply.
- `context-guard export` and `rollover` are explicit-only writes.
- Uninstalling plugin code does not automatically delete private runtime data.

To remove private data, first end or abandon dependent tasks, locate the
Codex-managed data directory for the installed plugin, review its contents, and
remove only that exact directory. Do not recursively delete a broad Codex home
or plugin cache root.

Plugin code archives live under `CODEX_HOME/plugins/cache-archive/`, separate
from private session data. They contain versioned public plugin files and a
SHA-256 index, not prompts, replies, transcripts, or task state. Archives are
never auto-pruned because already-open tasks may retain their absolute Hook path.

## Threat model and limits

Context Guard reduces accidental requirement loss, stale-summary reliance,
weak-evidence completion, binary evidence leakage, and authority confusion. It
does not protect against a malicious local process with access to the same
files, a user who intentionally shares raw plugin data, or an untrusted Hook
command. It is not encryption, a sandbox, or an authorization service.
