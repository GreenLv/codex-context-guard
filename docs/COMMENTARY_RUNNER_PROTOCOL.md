# Commentary causal probe protocol

The repository-only `cg-commentary-runner/v6` is an **offline, partial evidence
probe**, not native acceptance. Its source audit found that the previous
manual-compaction scenario cannot preserve the same active turn on official
Codex 0.153.4. Native collection therefore fails before starting a process.
Prepare checks local inputs and reports the missing contracts. The source
candidate includes an optional product trace reader; consumed installed caches
remain unchanged and have no acceptance of those new source bytes.

## Source contract: official Codex 0.153.4

All links below refer to the exact `rust-v0.153.4` release source. These are
implementation guarantees, not evidence that a particular native run executed
successfully. An installed binary's version/hash, private raw captures and
source-bound results remain separate acceptance inputs.

| Proposed edge | Source and guarantee | Concurrency / persistence limit | v6 treatment |
| --- | --- | --- | --- |
| RPC request → matching response | [`turn_steer_inner`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/app-server/src/request_processors/turn_processor.rs#L994) awaits `steer_turn`; core [`turn_input`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/turn_input.rs#L604) appends pending input before returning the active turn ID. | Expected turn is checked, but the model may still be processing earlier input. The reply has no model-request or answer ID. | Paired RPC edge. For steer, its meaning is only input enqueued for that turn. |
| Item start → same item completion | [`emit_turn_item_started` / `emit_turn_item_completed`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/mod.rs#L2422) retain item identity; [app-server canonical mapping](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/app-server/src/bespoke_event_handling.rs#L1082) emits lifecycle notifications. | [Command starts](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/app-server/src/bespoke_event_handling.rs#L1467) can be synthesized before canonical core starts for approval flows. Completion's fallback timestamp is not an observed start. Cross-item execution is not serialized by this identity. | Both notifications, same session/turn/item/type and unchanged command/cwd prove a local lifecycle pair only. Neither timestamp nor a lone completion supplies a start. |
| Submitted question → particular model answer | [`record_user_prompt_and_emit_turn_item`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/mod.rs#L4519) records history, preserves `client_id`, then emits user item events. The [turn loop](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/turn.rs#L305) drains pending input before the next model request, with documented initial-turn and post-compaction exceptions. | The current adapter has no verified source-bound link from that consumed input to a particular model response. Steer acknowledgment, arrival order and prose cannot supply it. | Unknown. Future work needs an audited input/model-response boundary and independent semantic review. |
| Commentary completion → later business invocation/result | [Turn streaming](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/turn.rs) and [event delivery](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/mod.rs#L2369) emit observations, not a general cross-item happens-before contract. | Multiple producers, asynchronous tools and presentation events prevent treating generic receipt or append order as business causality. Exit code zero alone does not prove the required business outcome. | Unknown; paired command lifecycle remains a local observation. |
| Active turn → manual compact → same active turn | [`thread_compact_start_inner`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/app-server/src/request_processors/thread_processor.rs#L2347) submits `Op::Compact`. [`handlers::compact`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/handlers.rs#L246) creates a new turn and calls [`spawn_task`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/tasks/mod.rs#L271), which first aborts existing tasks with `Replaced`. | An empty RPC response proves submission, not completion. This manual route replaces the active task. Inline automatic compaction is a different route and has not been wired or accepted here. | Unsupported route. Never issue this request as proof of active-turn continuity; block native collection. |
| PreCompact → compaction history installation | [`run_pre_compact_hooks`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/hook_runtime.rs#L528) awaits hooks; [local](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/compact.rs#L194), [remote](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/compact_remote.rs#L141), [remote v2](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/compact_remote_v2.rs#L168), and [token-budget](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/compact_token_budget.rs#L73) paths proceed only when allowed. | Implementation sequencing does not identify which observed Hook run belongs to which compaction. PreCompact does not establish a successful transcript flush. The current Hook summary lacks the needed invocation/trigger linkage. | Unknown across observations; no edge from Hook name or second-resolution clock fields. |
| Installed compact history → actual recovery trigger | [`replace_compacted_history`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/session/mod.rs#L3791) replaces history, persists checkpoint items, then queues `SessionStartSource::Compact`. [`run_pending_session_start_hooks`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/hook_runtime.rs#L124) dispatches the pending source. | Queueing is not execution. A `sessionStart` summary alone does not distinguish startup, resume or compact. Raw Hook trigger, source binding and cold recovery are still required. | Unknown; a fake resume label or model statement is never accepted. |
| Append/notification → durable source watermark | [`record_canonical_items`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/rollout/src/recorder.rs#L970) queues writes; [`flush`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/rollout/src/recorder.rs#L1009) separately awaits an acknowledgment. [`send_server_notification_to_connections`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/app-server/src/outgoing_message.rs#L597) normally enqueues without a write-completion callback. | Persistence policy, asynchronous queues, errors and concurrent producers matter. A generic line number is not proof that a question was sampled or a file was durably flushed. | No generic ordinal, receipt-order or flush edge. |

The two supported edge types form disjoint local DAG fragments. They are
constructed from paired observations, not accepted from a caller-supplied edge
list. Reordered delivery can preserve an identity pair, but cannot connect
fragments. Missing or foreign identities, revisions and conflicting duplicate
payloads cannot acquire authority through a later notification. Exact repeats
are idempotent. An early final answer stops the incomplete chain.

## Clocks and replay

Deadlines and elapsed values use integer `monotonic_ns` exclusively. Each
journal sample retains `mono_before_ns`, `wall_ns`, `mono_after_ns` and the
platform's declared resolutions. Resolution is **not an accuracy bound**.
There is no inferred wall range, constant wall-minus-monotonic offset,
intersection gate, calibrated tolerance or fitted drift correction.

Wall differences and native timestamp fields are diagnostic only. Hook
`startedAt` / `completedAt` use Unix seconds in the official
[command runner](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/hooks/src/engine/command_runner.rs);
item `*AtMs` fields use milliseconds. Missing, reversed, same-bucket, future-
looking or delayed wall fields cannot prove or disprove a causal edge. Identity
and required causal evidence remain mandatory regardless of these diagnostics.

Replay verifies saved samples, integer monotonic progression, paired completed
writes, responses, raw journal digest and the recomputed summary. It samples no
new clocks and cannot promote unknown coverage. Old v1–v5 plans and receipts
are rejected rather than rewritten or recertified. Their original evidence
must remain intact.

## Remaining gate

The mandatory chain remains: real main task, concurrent side question,
source-bound completed commentary, successful business continuation, real
active-turn compaction, genuine recovery trigger, independent semantic review
and source-bound cold recovery. No complete-chain success is available in v6.
Native acceptance remains `not_established`, including for a complete set of
synthetic local fragments. A reviewed design for the unsupported edges and a
fresh supervisor execution gate are required before another native attempt.

## Offline automatic-compaction adapters (unreleased)

`commentary_trace.py` reads bounded cold trace snapshots and joins an explicit
question input to completed commentary through the official inference call,
response, thread and turn identities. The user's `clientId` is checked against
its completed user-message event. Missing trace files, conflicting duplicates,
foreign identities and ancestor-only WebSocket input cannot establish the edge.
The official [`inference` recorder](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/rollout-trace/src/inference.rs)
records request/response payloads best-effort. The
[client](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/client.rs#L1828)
can record incremental WebSocket input; the adapter does not reconstruct it.
Trace logs, raw input, questions and answers stay in isolated private evidence.
The reader is shared with the packaged `cg_commentary_trace.py`. The product
collector selects the host's official session bundle itself and rereads the
host-selected transcript; callers cannot inject authoritative edges. Same-text
inputs with different client IDs or message IDs remain ambiguous. This exact
candidate mapping supports a distinct main task and side question in one turn,
not arbitrary repeated input or a missing historical trace. See the
[architecture contract](ARCHITECTURE.md#optional-commentary-source-binding-0142-candidate).
Completed native user fields come from the official
[`UserMessageItem`](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/protocol/src/items.rs#L77).
Ordinary progress before the question is excluded only when its exact response
is present before that question in a complete later input with a preserved
earlier-request prefix, or a unique completed `previous_response_id` chain
proves that the response was consumed before the new question. A branch,
duplicate or missing response, failed attempt or question in an ancestor
request stays unknown; notification order cannot replace a missing edge. The
end-to-end synthetic fixture includes initial progress; original same-turn
coverage remains mandatory.

`host_capture.py prepare/record --digest-echo` is optional and limited to
PreCompact and SessionStart. It records a fresh random capture identity and
returns only a `systemMessage` containing that identity and a domain-separated
raw-input digest. Default capture behavior remains empty JSON. Both the
[PreCompact parser](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/hooks/src/events/compact.rs#L279)
and [SessionStart parser](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/hooks/src/events/session_start.rs#L256)
retain this as a warning entry, separately from model context. The offline
`HookPairs` adapter requires exact source/run/turn/event identity, auto trigger
or compact source, and a one-to-one capture/run relationship. An exact duplicate
is idempotent; a reused capture across runs or a run paired to a second capture
fails. The echo proves neither trust, semantic completeness nor durable flush.
Changed capture commands still require official Hook review before native use.

`commentary_fixture.py` supplies a finite arithmetic/file fixture and independent
result oracle. A controller creates a fresh challenge only after the matched
commentary; the business result binds it, checks every row and emits at most
64 KiB of concrete validation output. The command is
`python -m tools.validation.commentary_fixture --input INPUT --challenge CHALLENGE --output OUTPUT`.
It exclusively creates OUTPUT. It starts no host or model. A compaction request
must contain the exact business result as one explicit function-call output,
or as the uniquely linked output of a model-visible `exec` code cell whose
child dynamic-tool call has the same identity and exact result. Arrival order
and a caller's success flag do not supply that dependency.
Unsupported output representations remain unknown.

Effective configuration comparison requires explicit matching
`model_auto_compact_token_limit` and `body_after_prefix` values; the caller must
separately establish the effective readback's source. A frozen threshold basis
must satisfy `before_business < limit + fallback_buffer <= after_business`.
Synthetic threshold tests are not a measured native threshold. Early, absent
or repeated compaction fails the scenario. No accepted native threshold is
claimed, and reports are never repeated to force a trigger.

The independent review must run through the existing production receipt
collector and product projection before compaction, then be rechecked after
actual recovery in a cold process. `product_review_checkpoint` reads that
projection and requires the information item to leave the current set while
distinct main obligations remain. It cannot consume a bare reviewer score.
Tests use a synthetic model boundary with the real receipt consumer and fresh
Python reload; they are not real-model acceptance.
The native observer supplies its validated plugin session directory and
isolated Host HOME to every review source read, barrier projection and cold
subprocess. A mismatched directory leaf or transcript root fails closed; the
repository harness's process-default HOME cannot stand in for either root.

The repository now also has a separate `commentary_live_runner.py` candidate.
It uses an owned official app-server process with paginated history, three
bounded dynamic tools, a frozen 11-Hook key/hash list, a source-bound answer
and business challenge, a reviewer receipt consumed by the product projection,
paired raw compaction captures, and a cold product read. Its local `--preflight`
checks paths and exact source/runtime inputs without starting Codex. The
`--execute` path requires separate producer and reviewer flags. One bounded
macOS native attempt reached the same-turn side question and completed
commentary, then failed before challenge release because the corresponding
inference-completed trace was absent at that instant. It did not reach business,
review, auto-compaction, or cold recovery; the attempt remains failed. A second
single-run attempt passed the answer binding and reached the business call,
then failed because the validator expected a direct `function_call` while the
official response carried an `exec` wrapper with a dynamic-tool child. It did
not reach review or compaction and remains failed. The offline repair binds the
inference response's model-visible call ID to `code_cell_started`, then the
code cell to the child `tool_call_started` ID and exact invocation. It also
checks the completed challenge child result and its outer output in the next
inference request; missing, conflicting, foreign or repeated edges remain
unknown or fail closed. A third single-run attempt crossed the nested business
barrier and reached review, then found that the observer resolved product state
under the process-default HOME rather than the isolated plugin data directory
used by the trusted product Hook. Its exact policy file in the default HOME
was removed; the offline observer repair now binds review policy, state and
cold readback to the isolated plugin data path and rejects linked or foreign
paths. The third attempt remains failed. The
fourth single-run attempt used the new installed runtime and trusted Hook set,
reached review, and then failed because the barrier independently resolved the
product session from the harness process's HOME. The retained source/trace can
build a review request only when both the plugin session directory and Host
HOME are supplied explicitly. That attempt produced one successful independent
reviewer receipt, but the business result was never released; automatic
compaction and cold recovery were not observed. The offline fix now carries both roots through the
barrier and fresh-process projection. The fourth attempt remains failed. The
older v6 entrypoint remains an offline-only probe. Injected wire tests do not
establish native acceptance.

The cold subprocess loads product state code from the pinned installed runtime
and the checkpoint helper from the pinned external source harness. Preflight
checks that helper's SHA-256; a cached or changed helper fails. The source
observer includes every completed user and commentary item when binding the
side answer, and accepts only one reducer-proven pair. Auto-compaction capture
selection ignores the ordinary startup `SessionStart`, then waits within the
compact deadline for one matching auto `PreCompact`, compact `SessionStart`,
and their Hook notifications. Repeat or foreign evidence fails. Reviewer and
cold-reader calls require 65 and 16 seconds respectively before launch, with
a separate process-cleanup allowance after the execution deadline.
The pinned Codex client [records inference completion on the provider's
terminal response event](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/core/src/client.rs#L2119-L2168),
after individual output items may already be delivered. The live controller
now holds challenge and business tool results while a matching attempt lacks
that terminal trace, polling only within the existing turn deadline. It
releases neither result on incomplete evidence; malformed or conflicting
sources still fail. A timeout is a missing edge, not proof that the host can
never provide it.
The native plan records only the configured 4096-token exploration limit and
its scope; it does not supply synthetic before/after token measurements to the
evidence chain. The frozen one-run ceilings are 60 seconds for startup, 240
for the active turn, 120 for compaction/recovery, and 15 for cleanup.

The live candidate remains gated on an observed auto-compaction threshold for
the actual model and prefix, the real Host's dynamic-tool and Hook event shapes,
same-turn answer behavior, completed installation, and cold recovery. The
planned 4096-token `body_after_prefix` limit is a bounded proposal, not a
token-calibrated native result. An official `compaction_installed` trace alone
still does not prove that `replace_compacted_history` completed. The producer
and independent reviewer now share an owned process-tree route. POSIX uses a
new process group; Windows starts the process suspended, assigns it to a
kill-on-close Job Object, then resumes it. Assignment, resume and cleanup
failures leave native acceptance unavailable. POSIX has offline process-group
tests. The Windows zero-model probe confirmed Job assignment and observed an
owned child alive after leader exit and exited after cleanup, with a separate
child process handle. This establishes the local cleanup route only; the
installed runtime and model chain remain unverified. A single turn can issue multiple inference or
compaction requests, so operation and wall deadlines are not a hard monetary
or token ceiling.
