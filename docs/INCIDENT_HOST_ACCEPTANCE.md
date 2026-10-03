# Two-incident native acceptance supplement

`incident_host/v1` supplements `native-acceptance/v2`; it does not replace its
portable installation gates. The runner is
`tools/validation/incident_host_acceptance.py`. It executes real models only
with the explicit `run` action without `--preflight`.

Prepare a clean exact source checkout, a dedicated scenario workspace, and an
isolated HOME installed through the safe installer. The coordinator establishes
login and reviews the nine Hooks through normal Codex trust. This runner never
logs in, copies credentials or trust, installs a plugin, changes the sandbox,
or answers an approval request. An official request interrupts observation and
is retained privately as a pending condition, not a product defect.

## Generate the concrete plan

Use the `plan` action with existing absolute paths for `--codex`, `--python`,
`--home`, `--cwd`, `--plugin-root`, and `--data-root`; supply `--model`, a new
`--plan-file`, and a new `--output` outside source and installed HOME. On Windows,
select the actual `.exe`, not a launcher. Supply `--shell` with the absolute
PowerShell path returned by the official local `environment/info` readback.
The plan pins its file hash; preflight verifies the file and the runner checks
the same official default shell before creating model turns. Extra shell
options or another executable path are rejected. The generator resolves paths, pins
CLI 0.160.0 version and bytes, Python version and bytes, clean source identity,
installed/source runtime equality, toolkit files, scenario manifest, model,
platform, and result location. An absent data root inside the isolated HOME
is allowed explicitly; normal Hooks create it at execution, never preflight. It emits concrete `preflight_argv` and `run_argv`
arrays. Execute the emitted preflight array before the run array; do not paste
unbound example paths into a shell. `--help` describes every required argument.

The preflight retains an exclusive input receipt beside the intended output.
It can be repeated for the identical plan and an unused result directory.
Changed inputs or an existing result fail visibly. Preflight performs no model
calls and proves neither authentication, Hook trust nor native behavior.

## What the runner observes

- An ordinary pause parks the existing work unit; polite resume retains its
  identity, pending requirements and verified source provenance. A typed wait
  remains waiting after the same polite resume.
- One ordinary model shell command per diagnostic turn runs the exact latest
  private `checkpoint-status --commands` binding. Same-turn paired trusted
  PreToolUse/PostToolUse, CLI command identity, output and exit code are checked.
  Unknown-option and missing-value commands remain fail-closed. A matched Pre
  refusal records CLI and Post as not observed and leaves this gate pending.
  The frozen source dispatch selects silent Pre, CLI exit 2 and a blocked Post;
  that observed branch is required to pass this diagnostic refusal gate. A missing attempted-command identity
  stays pending. Legal diagnostics with nonzero exit retain the separate source
  control: Post stays silent and the result never becomes business evidence.
  Private command output is retained only in the capture.
- A second ordinary model tool runs the read-only child against a byte-bound
  copy of that committed session in a collector-owned workspace fixture. Actual
  new-file and write-intent lock-open attempts must be denied; the CLI query
  must succeed with unchanged file and directory inventory. POSIX uses mode
  bits and a non-root effective UID. Windows uses a narrowly scoped current-SID
  deny ACL, retains its setup commands, and verifies the actual child principal.
  This proves the copied-session reader boundary, not a write-denial result for
  the live HOME. The direct diagnostic separately exercises the real HOME.
- Existing `stop_host/v1` supplies four positive Stops, a blocked completion
  followed by correction, actual compaction, and cold continuation in another
  owned app-server. Mapping replays the original RPC journals and state receipts
  instead of accepting the base receipt's status alone.

CLI 0.160 initial commands may use `agent` or `unifiedExecStartup`; the started
and completed sources must match. Manual user-shell and follow-up interaction
sources are rejected. The mapper accepts one exact standard shell wrapper,
checks the inner command's original bindings, and rejects nesting, additional
shell options, compound commands and expansion syntax. Windows native PowerShell
wrappers must match the planned absolute executable path and hash. Bare names
remain supported only for existing synthetic fixtures. This does not substitute for native
Windows acceptance or permit `readOnly` sandbox drift.

A fixed CLI token-redaction marker is display evidence, not a private control
token. Only that marker permits fixture token lookup in the unique discovery
command from the same paired trusted UserPromptSubmit Hook context. Executable,
script, data-root, session and turn must match; the token must verify against the
copied committed attempt's hash. There is no fallback to model prose, a new
token, a hash recovery or another turn. Unredacted displayed tokens still verify
directly. Successful CLI output must retain its observed turn/revision binding;
the query revision is distinct from the later post-Stop snapshot used by the
copied-session child. The four returned private commands must each match their executable, script,
subcommand, data-root, session, turn and committed token hash; the manifest
placeholder is the sole exception for the register-proof command. Missing,
duplicate or unbound observations fail visibly.

The nine-Hook inventory must be normally trusted and enabled. This inventory
check does not claim that all nine event types executed in these bounded scenes.
The runner checks owned process-tree cleanup and source/runtime stability again.
Unsupported ACLs, unavailable state or bindings, approvals, missing observations
and unfinished scenarios remain pending or fail the relevant evidence check;
none is substituted with a synthetic pass. Fixtures and failed logs are retained
for inspection. ACL/mode restoration is attempted before returning.

## Capture, replay and export

`run` creates private RPC journals, copied source records, requests, failures,
and `capture.json` using exclusive output. `artifacts.json` hashes the complete
capture. `map --capture-dir --output` checks the catalog and runs the same
production oracle without models. Both execution and current mapping identities
remain in the result. Output is exclusive; a retry uses a new result path and
preserves the original capture. Moving a capture requires retaining its internal
snapshot paths or explicitly preparing a separate reviewed transfer; replay
never silently rewrites source identities.

The result uses `incident-host-acceptance/v1`. Its ten named gates are `passed`,
`failed`, or `pending`; the whole supplement passes only when all pass. An
explicitly synthetic capture always exports `native_acceptance: not_run`, even
when every oracle passes. Exported results contain gate statuses and immutable
identities, with no raw prompt, transcript, token, tool output or private path.
These bounded scenes do not certify the original incident's entire state,
per-turn model telemetry, CI, or publication.

Run `tests.test_incident_host_acceptance` for the zero-model capture/mapping,
real diagnostic CLI, POSIX denial, Windows ACL adapter, drift, redaction,
approval, cleanup and exclusive-storage matrix. Native Windows ACL operation
and real model/Hook execution require separate coordinator-owned runs.
