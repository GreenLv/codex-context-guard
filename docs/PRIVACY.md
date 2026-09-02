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

The optional maintainer incident corpus is also outside this repository and is
not plugin runtime state. Its command-line tool keeps directories at `0700`
and files at `0600` on POSIX. On Windows it uses the native PowerShell ACL
surface to remove inherited access and grant full control only to the current
user, `SYSTEM`, and the built-in Administrators group, then reads the ACL back.
Failure to apply or verify that boundary stops the operation. CI consumes only
reviewed public fixtures and never reads a maintainer's private corpus.

## What the private store saves

Context Guard saves the user's prompt text in immutable per-prompt files so that requirements can be recovered after compaction or resume. It also saves the requirements and acceptance items derived from those prompts, together with their revisions and the session or turn identifiers needed to keep records in the right task.

Tool activity is stored as a bounded, redacted summary and outcome, not as complete stdout or file contents. Proofs keep the operation, object, result type, normalized counts, and hashes needed to check that evidence belongs to the user's actual requirement.

For images and other binary inputs, the store keeps a redacted basename or type, media facts such as byte count and dimensions, and hashes of the locator and content. It does not keep the image bytes or data-URL body.

Recovery and diagnosis keep compact checkpoints, delegated-result summaries, protocol versions, bounded status and reason values, and prompt or reply hashes. Schema 8 also keeps bounded identifiers and hashes for the selected instruction source, plan, host coverage, adapter version, and delegated actor when those values affect verification.

## What it does not save

Context Guard does not copy complete root or delegated-agent transcripts, chain-of-thought, full tool output, file contents, image bytes, credentials, authorization headers, plaintext private tokens, or URL query values into its ledger. Diagnostic Stop records keep hashes and bounded enums rather than raw assistant replies.

This distinction is important: user prompt bodies are saved privately for recovery, but the surrounding transcript and the model's hidden reasoning are not duplicated into plugin state.

## Minimization

- Evidence and recovery text are bounded.
- Binary/data-URL payloads are replaced by type, byte/character length, and
  SHA-256 metadata.
- Image bytes are read only within a 64 MiB bound to calculate hashes and basic
  dimensions; neither local-image bytes nor data-URL bodies are written to the
  ledger. Full local locators are represented by a hash and basename only.
- Scope manifests are normalized in memory. Stored proofs retain counts and
  SHA-256 digests, not the expected or observed identifier lists.
- Delegated-agent results are bounded summaries rather than transcripts.
- Recovery prioritizes active requirements and failures over historical detail,
  and reserves its completion rule even when lower-priority text is clipped.
- Transcript attachment reconciliation stores only bounded prompt IDs and scan
  state. Tool use scans a readable transcript at most once per pending prompt;
  compaction and resume may retry to recover late metadata.
- Disposition requests accept only a fixed disposition enum and derive a fixed
  reason enum; there is no free-form disposition reason field.
- The legacy `continue` enum is compatibility-only under Stop protocol 2.0.0;
  it is retained in bounded diagnostics but cannot force another model turn.
- Protocol and decision diagnostics retain hashes and bounded enums, never raw
  reply text, chain-of-thought, local paths, credentials, or plaintext private
  tokens. Recovery includes only the latest short fail-closed reason when
  relevant, not the decision history.
- Schema migration invalidates in-flight private tokens and staged controls
  instead of carrying turn authorization across protocol versions.
- Schema-5 items migrate as `legacy_fallback`; migration does not fabricate
  retroactive multimodal or semantic proof claims.
- Contract manifests are normalized to bounded identifiers, states, counts,
  and hashes. Status, diagnosis, and recovery do not expose raw manifest bodies,
  absolute source paths, prompt text, authority-bearing tokens, or Plan text.
- Native-plan binding persists a semantic digest and stale markers rather than
  a second editable plan.
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
- `register-proof` accepts a bounded JSON manifest, authenticates the current
  private turn, and stores only the normalized proof. Keep temporary proof
  manifests out of repositories and exports.
- `context-guard adopt <project-relative-json>` is root-user-only. It reads a
  bounded local manifest, stores its normalized hash-only contract, and cannot
  grant authority to natural-language or uncovered candidates.
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
weak-evidence completion, subset-as-complete errors, binary evidence leakage,
and authority confusion. It
does not protect against a malicious local process with access to the same
files, a user who intentionally shares raw plugin data, or an untrusted Hook
command. It is not encryption, a sandbox, or an authorization service.
Proof protocol 1.0.0 does not interpret arbitrary pixels or establish that a
source is official; it enforces only the deterministic obligations shown for an
`enforced` item.
