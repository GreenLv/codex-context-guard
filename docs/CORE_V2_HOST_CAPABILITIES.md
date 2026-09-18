# Core v2 host capability inventory (source candidate)

These are source-inspected capabilities, not native acceptance. The fixed
shared contract uses existing host events; it requires no invented Hook.

| Predicate/input | Codex adapter | DSH adapter | Trust and limit |
| --- | --- | --- | --- |
| Root input | UserPromptSubmit, immutable prompt ledger | persisted user/message with root origin | tool/model/delegated text cannot create root input |
| Tool call/result | PostToolUse tool_name/tool_input/tool_response; existing call observation | Session tool/call with callId/name/raw arguments, tool/result message.source.callId/error/meta | only host event intake; model receipts never enter trusted store |
| Persistence | locked atomic state and journal sequence | snapshotEvents plus sessions.flush(session) successful boolean | flush failure is unavailable, never empty success |
| File effect/readback | existing tool evidence and exact file subjects | write/edit plus independent file SHA readback | current content alone cannot prove historical creation/prestate |
| Test process | structured exit/result from supported process adapter | pinned bash/pwsh foreground result and materialized errors | zero exit proves process outcome; compound inner commands need independent attributable facts |
| Git commit/push | existing Git identity/readback adapter | existing readback producers; ordinary-host lineage adapter required | exact repo/tree/parent/OID/ref; shell prose does not establish identity |
| Final delivery | Stop final assistant reply and turn binding | current assistant final message/session turn | interrupted, intermediate, delegated and late replies do not close current information |
| External lifecycle | existing registered child/operation evidence | jobs/delegation snapshots with correlated operation ID | reply text cannot register a wait |
| Goal complete | existing guarded completion path | tool precommit callback for update_goal complete | only adopted completion contract; no scheduling/pause/restart |
| Release | adopted release adapter and actual intercepted surfaces | controlled registry publish reservation/settlement | ordinary opaque DSH shell is not an enforced channel |

Pinned DSH API inspected: Session 0.1.5-rc.1 `tool/call` fields
`turn,step,callId,name,arguments`; result fields `turn,step,message,error?,meta?`;
`message.source={kind:tool,callId}` and ToolResultBlock/isError. PTC dispatch
start/result requires matching correlation and the same durable replay checks.
Support for rc.2 is a separate adapter claim to verify, not inferred from rc.1.

No real-model task, host restart, platform-native run, installed cache, package,
network push or release is established here. macOS/Windows source branches are
portable candidates until each platform's authorized native acceptance. Missing
adapters report capability_unavailable, not missing permission.

Codex's normal PostToolUse carries the call input and result in one host event.
Any internal call/result pairing for that observation is a logical pair bound
to that same event, not proof that an independent PreToolUse call was persisted.
The standard/strict PreToolUse fast path remains stateless and silent.
