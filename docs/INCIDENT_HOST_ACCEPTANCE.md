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

For Windows exact-source materialization, start with a fresh no-checkout clone
and set only that clone's local `core.autocrlf=false` and `core.eol=lf` before
checkout. This is a maintainer source-materialization boundary, not a change to
product attributes, global Git configuration or installation instructions.

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
  bits and a non-root effective UID. Windows pins the actual ordinary-tool
  principal observed in the probe thread and applies an exact planned DACL only
  to owned fixture objects. API operation receipts and descriptor readback are
  retained separately from CLI commands.
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
shell options, compound commands and expansion syntax. For the principal and
read-only helper only, local absolute Windows Python/helper/request paths may
vary in slash direction or repeated separators. Arity and flags remain exact;
dot segments, case changes, 8.3 aliases, device/UNC names, alternate streams and
other path aliases are rejected. Helper identity binds the captured execution
repository and its pinned helper bytes, independently of the replay mapper
checkout; the Windows request path binds the captured workspace/output. POSIX helper argv stays byte-exact. Windows native PowerShell
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


## Windows fixture ACL policy and missing-observation supplement

The tools-only `specific-write-deny/v2` policy preserves the collector-owned
fixture's original allowed DACL. It applies a non-inheriting deny per regular
object: WD/AD/WEA/WA/DE, plus directory-only DC. It never denies generic W,
SYNCHRONIZE or READ_CONTROL, removes inheritance, or grants broad replacement
permissions. Objects are enumerated and checked for identity and reparse drift
before mutation. Original DACLs and protection/inheritance controls are saved;
The original inheritance model chooses restoration before mutation: non-AI
uses owner-authorized per-object SetFileSecurity; AI uses SetNamedSecurityInfo
with its saved protection flag. No failure-driven fallback converts models.
Unsupported control/request/default shapes reject before ACL mutation. Readback compares every ordered ACE byte, DACL revision
and presence/default/auto-inheritance/protection control, plus byte/stat identity.
Unrelated self-relative offsets and unused allocation padding are not permissions;
actual ACE additions or control changes always fail. Native tests save before/after
raw descriptors and contracts before teardown and retain failed fixtures.
Partial failures retain operation intent, actual native API return/error and
descriptor readback before restoration. Per-object restoration diagnostics
record the real API result and immediate readback, followed by the whole-fixture
strict check. Complete restoration is attempted on failure; an unverified
restoration stays a failure.

Windows collector and normal sandbox tool users can differ. Before restricting
the copied session, a real ordinary tool executes the pinned child helper with
`--identity` in the probe thread. Its official command scope, paired Hooks,
standalone argv, success and bounded output bind the SID. The later read-only
witness must execute in that same thread and report the same SID as the
restriction. The collector retains only its own restoration identity. Parent
or standalone-command probes do not certify a model-tool principal. Principal
drift, unavailable inherited read access, missing observations or write success
remain visible failures; normal sandbox and approval policy are unchanged.

`tools/validation/incident_host_supplement.py` defines the explicit
`incident-host-supplement/v1` contract for the retained six-stage partial batch.
It accepts exactly the five already-passed gates and five pending gates. Prepare
pins the original plan, result and complete catalog hashes, and binds a new
clean source/toolkit plan with identical runtime, installed plugin, HOME,
workspace, shell, CLI, interpreter, model, effort and scenario bytes. New output
is exclusive. Source and toolkit identities remain separate from the immutable
original execution subject.

Use `prepare --base-dir ORIGINAL --plan NEW_PLAN --output CONTRACT` with the
three mandatory `--base-catalog-sha256`, `--base-result-sha256` and
`--base-plan-sha256` inputs. Then invoke `run --contract CONTRACT --output
NEW_OUTPUT --preflight` with the actual arguments. Only the subsequent run
without `--preflight` executes models. It skips the five pause/typed scenes,
runs a fresh status anchor for current control binding, two negative diagnostics,
the Windows principal/read-only probe, and the existing Stop/compaction profile.
Fresh status and Hook observations are supporting anchors; they never overwrite
original passed gates. There is no resumed use of an ended turn's control token.

`map --contract CONTRACT --capture-dir NEW_CAPTURE --output NEW_RESULT` verifies
both complete catalogs and uses the production oracles before composition.
`incident-host-composed/v1` identifies each gate as original or supplement and
retains both execution identities. Changed original passes, extra or duplicate
stages/JSON fields, mixed origins, foreign snapshots, subject drift and missing
new observations are rejected. Restoration failure leaves cleanup pending.
Synthetic captures stay `native_acceptance: not_run`; only actual native
observations can close the missing native gates. Zero-model ACL mechanism tests
and composition fixtures establish input readiness, not model acceptance.

## Prepared v2 observation contracts

The tools-only source candidate recognizes an explicit `incident-host-plan/v2`
with `gate_profile: incident_host/v2` and both `observation_contracts` entries:
`negative: powershell-host-rejection/v1` and
`readonly_fixture: read-baseline-specific-write-deny/v3`. It does not infer
adoption from Windows, a shell, or an old failed capture. The v1 exit-2 contract
and all original failed results remain unchanged.

The prepared host branch accepts observed host exit 1 only for one exact pinned
PowerShell `-Command` wrapper, bound malformed argv and scope, silent Pre and
paired blocked Post feedback. The complete usage/error envelope must match a
prederived `negative_parser_reference` from harmless sentinel parsing under the
pinned Python and runtime bytes. Replay independently derives that reference;
only CRLF and usage wrapping whitespace vary. Noise, another parser/kind,
launch failures, extra commands and arbitrary nonzero exits fail. The result
reports `host_exit` and `source_exit: not_observed`; it never infers Python exit 2.
In v2 the normalized malformed argv also has exactly one token bound to the
copied current completion attempt. Only exact `[REDACTED_SECRET]` may use the
unique same-thread/turn paired trusted UserPromptSubmit discovery command; its
token hash must still match copied authority. Missing, duplicate, stale, foreign
or model-prose discovery cannot supply replacement authority. Unredacted values
are checked directly against the copied attempt. Old v1 retains its prior token
input domain and old failures. Existing direct/POSIX exit-2 observations keep
their original contract.

The v2 plan generator requires all three explicit options:
`--profile incident_host/v2`,
`--negative-observation powershell-host-rejection/v1` and
`--fixture-policy read-baseline-specific-write-deny/v3`.
Use its emitted `run --preflight` command with the actual output before a native
run. Preflight checks inputs and parser-reference bytes; it does not establish
host readiness, trusted execution or native acceptance.

Fixture v3 is one collector-owned transaction. Before any grant it durably saves
all original descriptors, controls, object identities, inventory and the original
restoration model. It rejects protected-tree overlap, reparse points, linked files,
unsupported ACEs and ownership drift. Read grants add only bounded non-inheriting
read/traverse rights to the actual pinned probe SID; other principals, deny ACEs
and DACL controls must remain exact. It then applies the existing exact create
and lock-write denial. Deny readback uses the verified object type: files require
`0x10116` (`WD,AD,WEA,WA,DE`); directories require `0x10156` with `DC` added.
It compares ordered ACEs without aggregating same-SID deny masks. Only one exact
explicit deny insertion in the canonical deny block, or an exact mask update of
one existing explicit deny, is permitted. Other ACEs keep their byte identity and
relative order; same-SID explicit grants lose only the exact requested deny bits
in the planned DACL. Duplicate, split, reordered or generic-right deny ACEs,
other-principal changes and control drift fail. Every exit attempts restoration to the pre-grant original,
including partial grant, deny, readback and interruption failures. An unverified
restoration remains a failure, with the original snapshot and receipts retained.

The ordinary principal helper and three additional baseline turns run in the same
normally trusted native probe thread as the final witness. The child observes
its SID before fixture resolve/stat/list/read, retaining controlled errors instead
of losing the actor on a read failure. The original baseline may pass or fail;
after the grant and after the deny, all reads must pass for the same observed SID.
Exact prompt, argv, cwd, thread, distinct turn, source helper bytes, paired Hooks,
phase and copied-request subjects are replayed. A standalone command/exec actor
cannot substitute for this native actor. The final witness must still observe
query exit 0, both denied writes, unchanged bytes and verified original restoration.

All new v2 request/phase digests use one shared sorted, compact UTF-8 JSON encoder
with literal Unicode and no Unicode or line-ending normalization. Only the outer
`request_sha256` is omitted from its hash. Unicode paths, nested values and local
command receipts therefore share one input domain. The v2-to-v1 internal oracle
adapter rebinds a private copy using the old encoder. It does not reinterpret old
captures: v1 retains its historical ASCII-escaped child validation, whose existing
literal-Unicode collector digest mismatch is outside this repair. Old v1 failed
subjects remain failed and are never replayed under v2 implicitly.

The v2 collector runs status, principal, three baselines, two malformed controls
and the final readonly witness. It runs no new pause, typed-wait, Stop, compaction
or cold scene. Its `required_gates` are Hook trust, status/PostTool, negative
controls, readonly and owned cleanup. `scenario_status` reports only that set;
the ten-gate `status` remains pending when omitted scenes are pending. A v2 standalone CLI exit 0 means only the required scenario set passed; its
printed aggregate and native result remain pending for omitted gates. Supplement
CLI exit 0 still requires the strict composed ten-gate pass. Partial
observations never become a full pass. Synthetic results always report
`native_acceptance: not_run`.

`incident-host-supplement/v2` joins three explicitly pinned subjects: the original
v1 partial batch's five passes; independently verified Stop/compaction components
from the retained failed v1 whole; and the newly observed v2 negative/readonly/
cleanup gates. Prepare additionally requires `--retained-dir` and its complete
catalog, capture, plan and, when present, result SHA-256 pins. Replay checks both
catalogs and the original Stop journals. It refuses duplicate scenes, changed
execution inputs, foreign origins, changed pins and relabeling of the old failed
whole. The composed result identifies each gate's subject and keeps the retained
whole marked failed. Only all ten constituent gates passing yields a composed
pass; this bounded mixed-subject result does not establish exact-source release
acceptance.

This is a tools-only source candidate. Zero-model tests use synthetic observations
and mocked Windows ACL operations; they establish parser, codec, transaction and
composition behavior only. Actual Windows grant/read/deny/query/write/restore,
model execution, host readiness and required full candidate gates remain separate.

### Exact planned-DACL API mechanism matrix

The current reviewed tooling source is `66e90790c1ef972cd2cc8b084025f736ffe1b6a6`; the accepted matrix/native execution remains at `329e5947cc5df0fbb865137aeb745e9e378359fa`. The helper still shares one exact planned-DACL builder and application route across v3 read grant, v3 write deny and v2 write deny. Required DACL controls, other-principal ordered ACE bytes and actor-mask rules remain exact. Intent, actual API result/error and readback failure are retained before rollback. The original helper and plugin runtime did not change in the latest fixture repair.

The repository entrypoint is `python -B -m tests.test_incident_acl_family --mechanism-matrix --cell-profile distinct-source32`. Supply actual `--actor-sid`, `--collector-sid`, full `--expected-source-commit`, `--expected-helper-sha256`, `--expected-runner-sha256`, `--output` and `--fixture-parent`; first use those same arguments with `--preflight`. Preflight checks all 32 plans without API calls, tokens or models. It cannot establish an executable token for a declared SID or certify native feasibility.

The explicit v3 profile uses `incident-acl-mechanism-matrix/v3` and `distinct-read-source-retention/v3`. It retains the 32 file/directory, control and actor-shape identities while constructing three distinct read/traverse sources and preserving the explicit management base. Protected directory descendants use `0x1404` in deepest-first order before S1; unprotected cells retain true inheritance. Coverage is not permission-equivalent to v1/v2. The earlier profiles and failed results keep their original contracts. See the [v3 fixture contract](ACL_MATRIX_FIXTURE_V3.md) for all mapped cells and strict supported inputs.

Fixture-side instrumentation verifies the exact live-buffer ACL passed to the original Named setter, captures API/flags and ordered hashes before writing, and invokes the setter once. Private raw ACL files remain outside public exports. This witness covers Named fixture construction only; raw assignment, business grant/deny and restoration retain their original checks. SDK mocks establish source forwarding, not Windows ABI or internal behavior.

Strict readback and whole-fixture restoration remain required. A failed cell stops the matrix after restoration is attempted; subsequent cells remain not_run. Earlier native matrix attempts at `57fe70c`, `7809df1`, `4a354e5` and `b8b861a` remain failed. The native Windows R4 `distinct-source32` matrix for `329e594` passed all 32 cells; each cell's v3, v2 and `setup_s0` restoration and the preservation guards were verified. The conditional full-v2 run then executed once but failed before its unified exec command could start. Its missing PostToolUse follows that launch failure; that original result remains failed. A subsequent complete R5 execution at `329e594` passed all ten gates through strict mapping at `66e9079`, as described below. See the [acceptance record](LOCAL_ACCEPTANCE.md) for the observed error and diagnosis boundary.

The matrix does not execute an ordinary model-tool actor. It cannot replace same-thread principal capture, three read baselines, actual denied writes, normal Hook trust or the exact-source ten-gate full host run. Earlier v1/v2/v3 request identities and failed captures retain their original subjects.

## Explicit full Windows v2 run

An absent `--gate-scope` preserves the existing five-gate `incident_host/v2`
behavior above. To run all ten gates from one clean source and fresh isolated
HOME, add `--gate-scope full` to the same explicit v2 plan command:

```text
--profile incident_host/v2 --gate-scope full
--negative-observation powershell-host-rejection/v1
--fixture-policy read-baseline-specific-write-deny/v3
```

Use all required absolute path/model arguments described above and execute the
emitted preflight array before its run array. The resulting plan, capture and
result use distinct `incident-host-plan/v2-full`, `incident-host-capture/v2-full`
and `incident-host-acceptance/v2-full` schemas, `gate_profile: incident_host/v2-full`,
`gate_scope: full`, and the complete ordered ten-gate `required_gates`. Their
manifest and plan hashes bind this adoption; missing, unknown or mismatched
scope/schema/profile/gate sets fail visibly. The old v1/v2 manifests and captures
keep their original meaning. Duplicate full-subject JSON fields are rejected.

The full collector executes the existing pause/resume and typed-wait scenes,
status/negative controls, same-thread principal and three fixture-v3 baselines,
readonly witness, then the existing positive/negative Stop, compaction and cold
continuation scenes. The Stop plan must match the full execution plan, including
source, runtime, installed plugin, HOME, workspace, CLI, Python, shell, model and
effort. Three owned-process cleanup receipts are required. Both `status` and
`scenario_status` require all ten gates; full CLI exit 0 cannot use the affected
five-gate shortcut. Synthetic captures always export `native_acceptance: not_run`.
The legacy supplement explicitly refuses full plans, captures and results; it
cannot drop full scenes or compose this run with older subjects.

A full native gate requires a fresh normally trusted HOME and an actual complete host run with bound source and packaged inputs. A tools-only prepared result, zero-model preflight or synthetic matrix does not certify that run. The coordinator owns normal trust, native execution and independent readback; release-source checks and final CI/HOL remain separate.

### Accepted retained execution and strict mapping

The R5 execution at `329e5947cc5df0fbb865137aeb745e9e378359fa` completed the full Windows profile. Its original mapper failed because restoration diagnostics changed the captured signed-request object after the ordinary tool had consumed the persisted request. The repair at `66e90790c1ef972cd2cc8b084025f736ffe1b6a6` separates mutable restoration state without changing the request digest, judge, helper or runtime.

The accepted offline derivation retains the original catalog and all four authored request hashes. It permits exactly the observed restoration-diagnostics addition, verifies all eleven restore objects/operations and the original durable receipt, then invokes the unchanged full mapper. All ten gates passed under the original execution identity and the new mapping identity. The original capture and failed result remain unchanged; no new model, ACL, setup, restore or collector run occurred. This R5-specific evidence path does not make the general mapper tolerant of changed digests or arbitrary capture repair, and does not establish unrelated historical cases. Full identities, result/provenance hashes and source controls are in the [acceptance record](LOCAL_ACCEPTANCE.md).
