# EvaluationContext retained storage (source candidate)

This inventory covers event-local retained storage. It is a deterministic
conservative accounting contract, not an RSS guarantee. Refused caches evaluate
again from the same authoritative sources; no scope or source verification is
skipped. Nothing survives an event except the existing persisted state.

| Storage | Accounting and lifetime |
| --- | --- |
| `_parsed` and `_ParsedText` | Text key/source, fragment text and per-fragment object reserve, entry/container bookkeeping and a 2x source-byte reserve for both lazy views; lexical event lifetime. |
| `_searches` | Source key, retained pattern/text, match spans and per-match/container reserve; immutable tuple of matches, lexical event lifetime. |
| `_source_clauses`, `_reply_clause_memo` | Text keys, every clause plus per-clause/entry reserve; immutable tuples, lexical event lifetime. |
| `_action_sources`, `_bases` | Full keys and values, including negative entries, with conservative container reserve; bases measured before deep snapshot allocation, readers get isolated copies; refunded at phase change. |
| `_prompt_record_memo` | Each distinct prompt identity and complete record measured separately against the aggregate projection budget; discarded at phase change. |
| `_root_records`, `_prompt_records`, `_disk_records` | Complete aggregate containers and contents conservatively charged even when also referenced by another cache; phase lifetime. |
| `_scope`, `_control_projection`, `_item_index` | Complete projection/index containers and referenced contents measured against the same projection budget; phase lifetime. An unadmitted control projection is recomputed, never marked as cached. |
| `_memo_costs` | Per-entry accounting keys share retained memo identities; fixed entry/container reserve covers charge-table cells and integers. Replacements refund prior costs, phase families refund exactly. |
| `_consumed` | One prompt ID and two source digests per consumed prompt, bounded by the loaded prompt catalog, event lifetime; integrity tracking remains even when all caches decline admission. |
| `state`, `session_dir`, `counters`, `phase_log` | References to already-loaded baseline state and caller-owned counters, one path and at most 64 phase entries. Baseline state is excluded because the cache does not copy it. New projection containers referencing it are accounted above. |

Text/memo storage has an 8 MiB aggregate estimate budget and secondary count
limits. Projection storage has a separate aggregate 32 MiB estimate budget.
Small memo traversal has depth 6, width 64, and the declared node limit.
Projection traversal supports depth 16, width 4096 and at most 200,000 nodes
so ordinary complete-scope workloads remain measurable. Cycles, unsupported
objects or any unvisited suffix return unknown and refuse retention. Traversal
does not serialize to measure. These limits bound admission work; transient
business evaluation and initial authoritative state loading remain separate.

Parsed fragments and view reserves include derived storage. String reserves use
four bytes per code point plus an object header; arbitrary-size integers use
a bit-length reserve; only exact built-in scalar/container types are supported; object/container bookkeeping uses deterministic reserves, rather
than a claim about a particular interpreter's allocator. Phase changes drop
all mutable state-derived projections; lexical entries retain content keys.
Caller mutation of owned projections is outside the supported read-only event
consumer contract. Source-consumption rechecks are independent of all cache
admission, phase refunds and projection recomputation.

Regression coverage includes deep/wide/cyclic/unsupported graphs, repeated
key refunds, parsed views, mutable basis isolation, one-million-byte prompt
records, multiple individually admissible records exceeding the aggregate
cap, source verification with no cache and the production Stop count oracle.
