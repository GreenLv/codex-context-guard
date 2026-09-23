# Privacy and Data Handling

## Independent reviewer candidate records

An explicitly invoked review sends the exact root, selected question span and
actual commentary text to the configured Codex model in a separate process.
The private `answer-reviews` directory retains the request, structured model
output and source digests to permit cold replay; this is an additional private
copy of that content. It follows session retention and must not be exported
with public diagnostics. No credentials are read, copied or stored by the
collector. The collector uses the existing authentication environment without
login or trust bypass. A local random MAC key seals captures; it is never
printed. Policy version/revocation is checked afresh. Hooks do not send content
to a model. A missing key or capture is unknown, never reconstructed from an
assistant claim. A successful run is review evidence, not native acceptance.


## 0.14.2 source candidate

When the host sets `CODEX_ROLLOUT_TRACE_ROOT`, the optional source-binding
reader discovers the official session bundle and reads complete bounded trace
and transcript snapshots. It reads raw model input/output in memory only;
it does not copy trace payloads into plugin state or contact a model. Derived
message observations and sealed review requests may additionally retain
`commentary-source-binding/v1` metadata: client, inference, response and message
identities, collector/root-record/manifest/event/payload hashes and source file device/inode pairs.
An excluded prior-progress proof may add a bounded causal-hop count and SHA-256
of the verified response chain; the chain's raw prompts and responses remain
ephemeral in memory.
`trace_as_of` contains the complete snapshot's relative filenames and hashes.
These private fields follow session retention and are excluded from public
diagnostics. Full prompt text used for matching remains ephemeral. The source
directory is supplied by the host environment, not a caller-selected receipt.
Local files remain inside the existing transcript trust boundary; this reader
does not authenticate a hostile process running as the same operating-system user.

Instruction/object fragments are ephemeral views of already retained root
text; they create no new persisted raw-text copy or hash domain. Current-fact
feedback is derived on read, not a new completion or delivery record. Default
diagnostics expose bounded state counts; complete source remains restricted
to the existing session-bound recovery/detail surfaces. Zero-model preflight
manifests and host schemas stay outside the public source tree; redacted
preflight results contain digests and reason codes, not credential contents.
The derived `commentary-observation.json` in the private session directory
retains bounded message/turn/root identities, Host completion time, source and
reply hashes, snapshot watermark, root question candidates and unknown coverage.
It stores no answer prose, credentials or additional raw transcript. It follows
the session's existing retention and private-file handling. Each read replaces only this derived observation snapshot. A hash/inode/byte
integrity anchor is retained to detect truncation, replacement and prefix edits;
it is never reused as message, answer or completion evidence. File identities
retain the existing five handle-stat fields; path/handle comparability checks
add no persisted fields. Each API retains its own before/after ctime check. Damaged/unavailable
current input does not reuse older observations as current truth. Recovery and
diagnostics show bounded counts/freshness only, and reject corrupted snapshots. No existing state or final-answer
ledger is migrated or promoted.

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

The unreleased schema-13 candidate adds a private monotonic event watermark,
per-prompt and per-host-call/result append numbers, UTF-8 byte offsets for
information and bounded execution children, and the root event's canonical
locator base/flavor in its immutable, hashed private prompt record (used only
for relative target identity).
Structured Git readback observations may retain commit, parent and tree OIDs,
branch and remote/refspec in private evidence; no Git command is executed by
the Guard. Stop diagnostics retain
bounded core predicate/coverage states and target digests, not a second raw
prompt copy. These fields stay in the existing private session directory and
follow its retention and redaction rules. Legacy events without append numbers
remain historical; migration does not infer a trustworthy sequence from
timestamps or assistant prose.

For opt-in Windows native acceptance only, `CONTEXT_GUARD_HOOK_TRACE_DIR`
may point to an already-created private directory outside the repository.
The PowerShell Hook entry writes one file per invocation containing a start
boundary and, if the product returns, an end boundary with elapsed
milliseconds and exit code. It does not write Hook stdin, prompts, paths or
credentials. An incomplete trace is diagnostic evidence of interruption,
not a successful Hook result. The host-run support journal and raw captures
also remain private and outside this repository; its shareable result bundle
allowlists status, gate names, digests and tool versions only.

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
For an attributable Host FileChange Update, schema-13 evidence may also retain
the SHA-256 of the stable post-image observed at PostToolUse. The later
independent readback stores its own hash and event sequence; neither record
copies the file bytes into the session state.
When a supported ordinary edit/readback/report or test/run/report root closes,
the item stores a bounded completion basis: the named predicate, event
watermark, Host evidence IDs, delivery digest, and shared-core projection
digest. The result text and file contents are not copied into that basis.
Recovery validates its Host and delivery references; missing historical
lineage cannot be inferred from a later reply or file state.
The ordinary completion store retains one source-bound result/delivery pair
for each distinct completed ordinary result while its item remains closed.
Thirty-two unreferenced diagnostic decisions and 512 unreferenced delivery
records may rotate; referenced pairs remain available for reload validation.
Their count is constrained by the completed items already in the session,
not an additional completion quota. No reply text or file contents are pinned.

For images and other binary inputs, the store keeps a redacted basename or type, media facts such as byte count and dimensions, and hashes of the locator and content. It does not keep the image bytes or data-URL body.

Recovery and diagnosis keep compact checkpoints, delegated-result summaries, protocol versions, bounded status and reason values, and prompt or reply hashes. Schema 12 additionally keeps a bounded response-delivery ledger. Each record stores the session and turn identifiers, the root work-unit id, the associated requirement ids, the event source (a trusted Stop final reply or a migration reconstruction), the reply SHA-256, the delivery status, a resolution value, the canonical delivery digest, a sequence number, and a timestamp. The reply hash is the only representation of a delivered answer: reply text is never copied into the ledger. The ledger follows the same retention and cleanup policy as the rest of the private state, becoming eligible for cleanup 30 days after its session ends. Schema 11 also keeps bounded work-unit lifecycle states and identifiers, candidate-closure and readiness digests, ticket lifecycle state, normalized tool-input hashes, and exact release identity fields when those values affect authorization or verification. Wait conditions store bounded enums, identifiers and hashes (condition id, owner unit, typed raise/release source, source-clause and subject hashes, optional registered child-lifecycle hash, and status); they never store the prompt or tool text that raised or released them. Explicit session restrictions retain an exact span into their existing immutable prompt record. Session-bound recovery pages can read that complete original text and verification metadata in bounded chunks; default diagnostics remain counts, identifiers and hashes. The runtime does not duplicate raw tool input or action-bearing tokens. Commit authorization retains bounded repository-relative Git paths, status/mode/blob identities and the root file ceiling because exact object comparison requires them. Paired observations retain input/call hashes and bounded authorization-generation references rather than commands or file contents. Direct-push decisions retain only the call hash, exact redacted target, allow/deny enum, and the selected authorization generation for an allow. Early schema-11 state without that bounded decision list is upgraded to an empty list after its older observations pass integrity validation; the upgrade adds no inferred decision. The immutable file ceiling also records whether further verified edits are required before freezing source; readiness does not come from a nonempty dirty tree alone. Exact ordinary-push target facts are private authorization metadata; credential-bearing URL authorities, queries and fragments are not accepted by this observation path. These records are not exported into public diagnostics or this repository.

## What it does not save

Context Guard does not copy complete root or delegated-agent transcripts, chain-of-thought, full tool output, file contents, image bytes, credentials, authorization headers, plaintext private tokens, or URL query values into its ledger. Diagnostic Stop records keep hashes and bounded enums rather than raw assistant replies.

This distinction is important: user prompt bodies are saved privately for recovery, but the surrounding transcript and the model's hidden reasoning are not duplicated into plugin state.
For schema 13 provenance, the immutable prompt record also retains the Host
turn identifier when provided, covered by its record hash. This bounded
identity lets a late tool result be associated with its originating root;
legacy prompts without it remain unknown. No PreToolUse transcript or tool
content is added for this association.
Schema 13 also retains bounded root-control records for direct persistence,
pause, resume and cancellation. Each stores the original prompt record hash,
UTF-8 control and object spans, event sequence, work-unit id, scoped ordinary
requirement ids, action kinds and a catalog digest. A required test child's
parent repair id and its own source span/hash are stored with the requirement.
The original prompt body remains only in its existing private immutable
record; Stop decisions store a bounded normalized control summary, not another
copy of the request or Host output. Old states without these source fields do
not acquire them from later text or migration.
For a newly recorded human business root, a separate private `prompts/units`
companion binds the original prompt-record hash and event sequence to its
work unit. It contains identifiers and hashes, not another prompt body. A
missing companion, a shortened requirement inventory, or an unsupported
replacement link cannot be reconstructed from a final status label or a
rehash of the mutable state; recovery leaves controls untrusted.
If a crash leaves an immutable prompt record ahead of the last saved state
watermark, the older catalog is likewise not certified. Recovery replays the
prompt as an unverified obligation; it does not infer a missing unit binding.

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
- The legacy `continue` enum is compatibility-only under Stop protocol 2.1.0;
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
- Action tickets retain bounded repository and release identities plus hashes
  for candidate closure, readiness, execution contract, and normalized tool
  input. They never retain raw commands, complete tool arguments, credentials,
  or private absolute paths.
- Work units retain bounded identifiers, parent relationships, kinds, and
  prompt bindings. Default status output exposes only current-unit counts and
  bounded summaries; full or item audit output must be requested explicitly.
- Default Stop feedback is anonymous by contract: it names only the current
  work unit's pending-item count, one reason, and one next step — never
  requirement, acceptance, or evidence IDs, which stay in `diagnose` and
  explicit audit views.
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

### Release posture during state failure

Version 0.13.1 keeps a private `release-required` latch beside session state.
It contains only the `release-posture/v1` schema marker, never prompts, targets,
identities or credentials. A separate `action-profile.json` contains only its
`action-profile/v1` schema and last verified profile enum. It lets ordinary
sessions retain their default routing when the main state is unreadable. Saving explicit release mode creates it before the
state write; a verified exit removes it after the new state is saved. Corrupt
state cannot remove this marker or silently disable release verification. Both files
share the session retention and deletion policy and are not exported. This is
fault recovery for managed state, not protection against arbitrary filesystem
deletion. PreToolUse reads posture without writing, locking or recovering state
on the standard and strict paths.

The answer-review/v2 candidate adds the exact question catalog, explicit semantic
message associations, source row ordinals and bounded per-input attempt markers
to private review data. Associations remain model judgments; they are not new
Host fields. No legacy v1 receipt is silently promoted.
