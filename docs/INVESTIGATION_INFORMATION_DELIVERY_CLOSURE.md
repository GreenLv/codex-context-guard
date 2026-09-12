# Information delivery and execution continuity

Status: 0.13.5 source-candidate investigation. This document describes synthetic reproductions and source changes, not installed or native-host acceptance.

## Defect and scope

A request such as "帮我讲一下这个仓库" has a reply as its deliverable. The old live delivery path accepted interrogative questions but could leave this imperative explanation pending after a delivered answer. Later recovery could therefore show an already-answered request as unfinished.

That defect does not explain every return to an old question after compaction. Codex owns context-window replacement, notes and history retrieval. Guard can preserve a continuation request even when the executing agent fails to follow it. Answer closure and execution continuity need separate regressions.

## Repairs

1. **Reply-only requests.** The live delivery path accepts an imperative explanation only when every coordinated request is informational. A known execution command, a normative constraint, an enforced proof contract, unresolved asset reference or unknown coordinated instruction keeps the requirement open. A how-to question may mention an executable without requesting its execution.
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

The earlier proposed fix treated the absence of a small set of action words as proof that a prompt was informational. It incorrectly closed "execute pytest and summarize" with no execution evidence and dropped polite acceptance requirements. The current fix checks the shape of every coordinated request as well as its operations, so unknown instructions remain open.

## Evidence and limits

Focused current-source tests pass on Python 3.12 on Windows. The previously reported isolated Stop-subject failure was not reproduced in the later review: all 20 tests in that module passed. It must not be carried forward as a confirmed current defect. Full-suite results and host restrictions are recorded in [local acceptance](LOCAL_ACCEPTANCE.md); a synthetic dispatch is not a real desktop Hook capture.

Historical delivery reconstruction remains frozen. Already-pending items are not silently repaired or marked verified from a later reply. A delivered answer is not proof that its content is correct, and unsupported execution evidence remains visibly `legacy_fallback`.

The 0.13.4 candidate was consumed by isolated installation before these runtime changes. Version 0.13.5 keeps old caches immutable and requires fresh artifact evidence before installation or release claims. No real session ledger is rewritten by this repair.
