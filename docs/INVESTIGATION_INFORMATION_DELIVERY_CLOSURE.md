# Information delivery and execution continuity

Status: 0.13.6 source-candidate investigation. This document describes synthetic reproductions and source changes, not installed or native-host acceptance.

## Defect and scope

A request such as "帮我讲一下这个仓库" has a reply as its deliverable. The old live delivery path accepted interrogative questions but could leave this imperative explanation pending after a delivered answer. Later recovery could therefore show an already-answered request as unfinished.

That defect does not explain every return to an old question after compaction. Codex owns context-window replacement, notes and history retrieval. Guard can preserve a continuation request even when the executing agent fails to follow it. Answer closure and execution continuity need separate regressions.

## Repairs

1. **Reply-only requests.** The live delivery path accepts an imperative explanation only when the complete request matches a bounded information grammar. Unknown syntax stays pending, even when it follows a recognized explanation prefix. A known execution command, a normative constraint, an enforced proof contract, unresolved asset reference or unknown coordinated instruction keeps the requirement open. A how-to question may mention an executable without requesting its execution.
2. **Acceptance criteria.** A question mark or polite prefix does not erase a validation requirement. Only reply-only inquiries without normative constraints are omitted from acceptance extraction.
3. **Bounded continuation.** A direct root request to continue execution is recognized independently of quoted or hypothetical instructions. If the reply itself still names authorized assistant work as a next step, Stop uses its existing single-correction budget. A real user handoff or external wait still yields normally; the request is not converted into unlimited persistence.
4. **Diagnostics.** An uncertified whole-completion claim over pending items remains distinguishable from an empty completion scope. This adds no public control metadata.

These are Stop and delivery changes. They add no default tool veto, execution-approval chain, new Hook event or schema. Release enforcement remains opt-in and unchanged.

## Regression examples

| Request | Required result after a bare answer |
| --- | --- |
| 帮我讲一下这个仓库的主要内容，以及实现的核心逻辑 | answered |
| How do I run pytest? | answered |
| 你继续执行，然后总结结果 | pending |
| 按你的计划执行，然后说明结果 | pending |
| 执行 pytest 并总结结果 | pending |
| Explain the project and frobnicate the workspace | pending |
| 请验证所有测试通过 | acceptance retained; pending |
| 请确保测试全部通过，可以吗？ | acceptance retained; pending |

The production-dispatch regressions in `tests/test_information_delivery_closure.py` use isolated synthetic state. They cover delivered answers, promises, unknown commands, mixed requests, normative questions, compact/resume, bounded correction, genuine waits and frozen migration behavior. Existing delivery and Stop-subject suites cover stale, unbound and conflicting delivery identities.

The earlier proposed fix treated the absence of a small set of action words as proof that a prompt was informational. It incorrectly closed "execute pytest and summarize" with no execution evidence and dropped polite acceptance requirements. The 0.13.5 follow-up still accepted unknown tails under alternative connectors and an independent operation scan rejected "how do I publish a version?". The 0.13.6 grammar consumes complete clauses and their topics; it does not treat absence from an action dictionary as proof of information-only intent. Supported how-to operations use that same scope. Unsupported wording remains pending, including complex information requests; this is a conservative language boundary, not universal natural-language understanding.

## Evidence and limits

Current-source production-dispatch regressions cover complete information clauses, how-to operations, unknown verbs and connectors, temporal tails, normative constraints, and recovery projection. See [local acceptance](LOCAL_ACCEPTANCE.md) for executed results and platform boundaries. A synthetic dispatch is not a real desktop Hook capture.

For supported how-to prompts, complete tutorial steps such as "先运行测试，然后创建标签并发布版本" can count as answer delivery. This is a delivery-only distinction: a first-person promise, waiting request, unfinished answer, or unrecognized step sequence retains the original Stop observation. It does not grant tool access or weaken proof or delivery-identity checks.

Historical delivery reconstruction remains frozen. Already-pending items are not silently repaired or marked verified from a later reply. A delivered answer is not proof that its content is correct, and unsupported execution evidence remains visibly `legacy_fallback`.

The 0.13.4 candidate was consumed by isolated installation before these runtime changes. Version 0.13.6 keeps old caches immutable and requires fresh artifact evidence before installation or release claims. No real session ledger is rewritten by this repair.
