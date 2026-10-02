# Instruction routing and GPT-6 validation

The resident Skill carries the completion contract and short discovery routes.
Advanced operations are read only when needed. Removing repeated instructions
does not remove runtime checks or lower authority, integrity or evidence rules.

| Requirement | Maintained location |
| --- | --- |
| Current work, required descendants and ancestor constraints | Skill completion scope; architecture work-unit contract |
| Recovery, original requirements and explicit supersession | Skill recovery section; architecture and source-bound runtime checks |
| Separate source, execution, artifact, installed and native evidence | Skill evidence section; acceptance and proof checks |
| User and host authority; ordinary tools remain approval-free | Skill authority summary; `references/authority-and-controls.md`; default-path regressions |
| Advanced proof and release operations | `references/advanced-completion.md` and `references/authority-and-controls.md`; adopted runtime contract checks |
| Private command discovery | `checkpoint-status --commands`; default status omits the command list |
| Independent answer review, one execution and unknown coverage | Skill short route and `references/answer-review.md` |
| Delegated results and successor handoff | Skill delegation route and `references/successor-pack.md` |
| Multimodal facts, privacy and unavailable capabilities | Skill asset summary, privacy specification and state schema |

Reference paths in this table are relative to `skills/context-guard/`.
Advanced commands are not required merely because the Skill loaded. Normal
completion needs no bookkeeping command. Hooks do not call a model, and model
names never select weaker verification rules.

Against published 0.14.3, resident Skill text changed from 8,017 to 4,582 UTF-8
bytes and from 1,560 to 932 tokens using tiktoken 0.13.0 with `o200k_base`.
Two fixed ordinary Hook prompts changed from 771/752 to 302/306 tokens while
preserving their complete requirement and acceptance set. Optional reference
text is excluded from resident counts; actual reads belong in workload usage.

The observed host exposed GPT-6 Astra, Sol and Luna, not GPT-6.1 Sol. All three
passed the bounded Stop, correction, compaction and cold-resume comparison.
Full-request usage includes host context and is reported separately in
[local acceptance](LOCAL_ACCEPTANCE.md); text-size reductions are not a claim
of equal model-cost reductions. There is no fixed percentage target for
model-input savings without a measured workload baseline.
