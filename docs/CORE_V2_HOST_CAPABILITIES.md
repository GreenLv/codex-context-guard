# Core v2 host capability inventory (source candidate)

These are source-inspected capabilities, not native acceptance. The fixed
shared contract uses existing host events; it requires no invented Hook.

| Predicate/input | Codex adapter | DSH adapter | Trust and limit |
| --- | --- | --- | --- |
| Root input | UserPromptSubmit, immutable prompt ledger | persisted user/message with root origin | tool/model/delegated text cannot create root input |
| Tool call/result | PostToolUse tool_name/tool_input/tool_response; a string response needs a matching Host session-transcript terminal item observed during that Hook | Session tool/call with callId/name/raw arguments, tool/result message.source.callId/error/meta | exact session/turn/call/input/cwd correlation; model receipts and quoted output never enter trusted store |
| Persistence | locked atomic state and journal sequence | snapshotEvents plus sessions.flush(session) successful boolean | flush failure is unavailable, never empty success |
| File effect/readback | one-target Host FileChange plus separate bounded current file readback; exact file subjects | write/edit plus independent file SHA readback | a patch receipt alone cannot prove required content or historical prestate |
| Test process | matching Host CommandExecution integer exit for a supported single-suite process | pinned bash/pwsh foreground result and materialized errors | zero exit proves only that process outcome; arbitrary npm/Python commands and compound inner commands need separate attributable facts |
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

Codex's normal PostToolUse carries the call input and a response in one Hook
event. CLI 0.153.4 can give Bash and apply_patch a bare string response,
including for a failed Bash command. For that wire, the Codex adapter accepts
only a bounded Host session-transcript `item_completed` already present when
PostToolUse runs, with matching session, turn and call ID, plus exact command/cwd
for CommandExecution or a single matching change target/type for FileChange.
The Host terminal status and exit remain separate from output text. A missing,
late, ambiguous or oversized record is unavailable at that observation
watermark; later facts cannot change an earlier Stop. Internal call/result
pairing remains a logical observation, not a persisted independent PreToolUse
call. The standard/strict PreToolUse fast path remains stateless and silent.
The observed Add FileChange carries post-image content; the observed Update
carries a unified diff instead. The adapter validates each against the one
Hook patch operation and requires a separate current file readback for
completion. Native Delete FileChange shape is not established by these inputs.
