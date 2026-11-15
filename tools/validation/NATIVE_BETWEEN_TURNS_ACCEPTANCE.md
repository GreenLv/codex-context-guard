# Between-turns native acceptance — 0.18.0

This entry checks a compatible daily upgrade while Codex remains open. It runs
an old task before and after the switch in the same owned CLI app-server, then
runs a fresh task and observes its real Hook execution. The operator must wait
for a turn to finish and pause new operations in the shared configuration until
the switch completes. The process observation is a bounded snapshot, not a
lock on other clients.

The [acceptance report](https://github.com/GreenLv/codex-context-guard/releases/download/v0.18.0/context-guard-0.18.0-acceptance.json) identifies exact-package native results on macOS and Windows. This procedure uses the normal account and can change the
daily installation through the maintained official upgrade tool; it uses real
model turns. It does not create a login or bypass Hook trust. A CLI stdio
app-server is not a Desktop GUI observation: the result explicitly records
`gui: unobserved`. On macOS, identify the actual Codex host executable used by
the maintained plan, including when it is inside ChatGPT.app; do not substitute
an unrelated application path. The CLI and Desktop host are separate inputs.

## Prepare the inputs

Use the reviewed public product checkout at a clean, exact commit. The native
producer must be tracked there. Prepare the target ZIP and extracted artifact,
the published 0.17.3 ZIP and its retained verified extracted artifact, and a
v2 [daily upgrade plan](DAILY_UPGRADE.md) for the same CLI and artifacts. The
checkout's distribution files, target ZIP and extracted target must agree;
the old ZIP is checked against the producer's published-release pin and the
retained old artifact. The installed old cache must match that artifact. The
new version cache must not already exist at preflight.

Before `--run`, enable and normally review all nine Context Guard Hooks for
the installed old version in the selected Codex configuration. Open `/hooks`
in the CLI, or **Review hooks** / **Settings > Hooks** in Desktop; see the
[official Hook review instructions](https://learn.chatgpt.com/docs/hooks).
The old Hooks must already be trusted when the run starts. The producer's
bounded review wait applies to the newly installed version.

Use the daily-upgrade guide for its v2 plan fields. For this native experiment,
run only its read-only `--preflight-commands` check before the native phases,
as shown below. Use the same future `OUTPUT` path; this check does not create
it. The native `--run` creates its own batch at `OUTPUT/maintained` and invokes
the maintained tool's `--resume`, which prepares, applies and verifies that
batch. Do not separately run the standalone daily guide's `--prepare`,
`--apply` or `--resume`, or create another daily batch for this experiment.

The native plan is a private JSON file with exactly the fields below and the
optional waits. All paths are absolute; files must be regular, single-link
inputs and paths must not traverse links or reparse points. `repo`,
`codex_home`, `workspace`, `data_root` and `artifact` are existing directories.
`workspace` must equal `repo`; `data_root` must be inside the selected daily
`codex_home`. That HOME must be the one the maintained daily tool would use.
The output parent must already exist and be private; choose a new output
directory outside the checkout, HOME and artifact. The tool keeps records
private because they can contain local paths and process facts.

| Fields | Value to provide |
| --- | --- |
| `schema`, `transition_strategy`, `declared_pause` | `cg-between-turn-native-plan/v2`, `between-turns`, and `true`. The declaration records the operator's between-turn pause; it cannot enforce it for other clients. |
| `config_refresh` | The literal `reload-user-config-empty-batch`. After normal Hook review, the owned app-server performs one version-bound empty configuration batch and verifies that the user configuration file remains unchanged. |
| `old_version`, `target_version` | `0.17.3` and the reviewed target version, `0.18.0` for this version. |
| `repo`, `workspace`, `codex_home`, `data_root` | The exact reviewed checkout, the same checkout as workspace, the daily Codex configuration directory, and its existing Context Guard data root. |
| `cli`, `maintained_tool`, `maintained_plan` | Exact Codex CLI, the checkout's `tools/validation/daily_upgrade.py`, and the private v2 between-turns plan. Its target artifact and CLI must match the native plan. |
| `zip`, `artifact`, `old_zip` | The exact target ZIP, its extracted artifact root, and the published old ZIP. The v2 daily plan names the retained old extracted artifact through `old_artifact_dir`. |
| `commit` | The full 40-character lowercase Git commit at the clean checkout. |
| `tool_sha256`, `cli_sha256`, `zip_sha256`, `maintained_plan_sha256` | Lowercase SHA-256 of the maintained tool, selected CLI, target ZIP and exact daily-plan bytes, respectively. |
| `runtime_sha256`, `old_runtime_sha256` | Lowercase runtime-tree digests of the target and old artifacts. Use the repository's runtime identity calculation; the old digest must also match the producer's published pin. |
| `old_source_sha256` | SHA-256 of `hooks/hooks.json` in the retained old extracted artifact. |
| `read_file`, `native_read_sha256`, `read_file_safe_for_model` | The checkout's tracked, clean `README.md`, its lowercase SHA-256, and `true` to declare that its contents may be sent to the selected model. No other file is accepted as this fixture. |
| `expected_cli_version`, `expected_model`, `witness_mode` | Exact output of the selected CLI's `--version`, the expected real OpenAI model name, and `unknown` for the current runtime-path witness. |
| `windows_backend` | Required only on Windows: the literal `mxc`. Omit on macOS and other platforms. |
| `trust_wait_seconds` | Optional integer 1–1200; default 300. This bounds the normal new-Hook review wait. |
| `activity_wait_seconds` | Optional integer 1–900; default 120. This bounds the producer's observation of old runtime activity. The v2 daily plan has its own bounded drain. |

Do not add `_native_plan_sha256`: it is reserved and derived from the plan
bytes. Other extra fields are refused. The real model session requires the
official OpenAI provider and default endpoint, without a custom model catalog;
the producer checks that configuration and the model readback. It also binds its own bytes,
the maintained tool's helper closure, the artifact manifests, the selected
CLI, model/provider readback and the retained plans and receipts. A changed
bound input requires a fresh review and batch.

On Windows the acceptance profile selects MXC, a native Windows process-isolation
backend, so the standalone CLI's isolation choice is explicit for the controlled
read-only task. This plan selection starts the owned CLI app-server with the fixed
one-process override `-c 'windows.sandbox="mxc"'`; it does not change saved
configuration. The producer checks that the effective `config/read` value is
`windows.sandbox = "mxc"` in each observed phase and the independent reader
rechecks that selection and the exact saved launch arguments. A missing or
refused selection stops the run; there is no automatic fallback. This records
the requested and effective configuration selection, not a direct observation
of the operating system's sandbox backend. A Desktop client may use a different
profile. The read-only sandbox and on-request approval requirements remain in
effect.

This refresh mode is limited to the reviewed `codex-cli 0.169.0-alpha.11.1`
macOS and Windows binaries pinned by the producer. A different binary or CLI
version is refused; matching this pin does not prove how that binary was built.

From the reviewed checkout, a verified Python 3.10+ interpreter can calculate
the file SHA-256 and the repository's runtime-tree identity as follows. Replace
the placeholders with absolute paths; on Windows use the selected Python
interpreter in place of `python3`.

```sh
python3 -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' FILE
python3 -c 'import pathlib, sys; from tools.validation.stop_host_acceptance import runtime; print(runtime(pathlib.Path(sys.argv[1])))' ARTIFACT_ROOT
```

## Run the phases

Run a launcher from the checkout. Replace `PLAN` and `OUTPUT` with absolute
private paths; the same fresh `OUTPUT` can be used for preflight and run
because preflight does not create it. Each phase below starts only if the
previous phase exits with code `0`; on any other result, inspect the retained
records before taking another action. `MAINTAINED_PLAN` is the daily v2 plan
referenced by the native `PLAN`.

For this controlled experiment, keep other clients and tasks paused until the
whole chain ends successfully: `--run` reports `passed_cli_native`, then
`--verify-result` reports `reverified_read_only`, both with exit code `0`.
Completing Hook review alone is not the signal to resume other operations.
If the chain stops, keep the pause while the coordinator checks the installed
state and retained batch; installation may already have occurred.

```sh
tools/validation/run_daily_upgrade.sh daily --plan MAINTAINED_PLAN --output OUTPUT --preflight-commands && \
tools/validation/run_native_acceptance.sh between-turns --plan PLAN --output OUTPUT --preflight && \
tools/validation/run_native_acceptance.sh between-turns --plan PLAN --output OUTPUT --run && \
tools/validation/run_native_acceptance.sh between-turns --plan PLAN --output OUTPUT --verify-result
```

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $dailyUpgradeEntry = '.\tools\validation\run_daily_upgrade.ps1'
    & $dailyUpgradeEntry -Target daily -Arguments @('--plan', 'MAINTAINED_PLAN', '--output', 'OUTPUT', '--preflight-commands')
    if ($LASTEXITCODE -ne 0) { throw 'Command readiness stopped; inspect its result.' }
    $nativeAcceptanceEntry = '.\tools\validation\run_native_acceptance.ps1'
    & $nativeAcceptanceEntry -Target between-turns -Arguments @('--plan', 'PLAN', '--output', 'OUTPUT', '--preflight')
    if ($LASTEXITCODE -ne 0) { throw 'Preflight stopped; inspect its result.' }
    & $nativeAcceptanceEntry -Target between-turns -Arguments @('--plan', 'PLAN', '--output', 'OUTPUT', '--run')
    if ($LASTEXITCODE -ne 0) { throw 'Run stopped; retain and inspect the batch.' }
    & $nativeAcceptanceEntry -Target between-turns -Arguments @('--plan', 'PLAN', '--output', 'OUTPUT', '--verify-result')
    if ($LASTEXITCODE -ne 0) { throw 'Verification stopped; inspect its result.' }
}
```

1. `--preflight` only reads inputs and official installation state. It checks
   the plan, exact source and artifacts, old installation and command identity;
   it starts no app-server or model and does not install anything. A successful
   preflight is input readiness, not native acceptance.
2. `--run` creates the private output, starts an owned app-server and checks
   normal trust for the old Hooks. It runs an old task with a pending requirement,
   waits for the turn boundary and old runtime activity, then invokes the
   maintained daily upgrade. The official plugin add may remove the old cache.
   Keep new operations paused throughout the switch.
3. If the new Hooks need normal review, review all nine for the target version
   through `/hooks` or Desktop's **Review hooks** / **Settings > Hooks**, using
   the same Codex configuration while the bounded wait is active.
   When installation already landed, the producer
   continues with verification after review; it does not repeat plugin add.
   After trust is observed, the producer reads the active base user layer,
   requires exactly one active base user layer and no combined `trusted_hash`
   values awaiting automatic splitting. If these conditions are unmet, it stops
   and preserves the batch; do not hand-edit trust fields to pass this check.
   It sends one empty batch bound to that layer's version, verifies unchanged
   file identity and bytes, then
   checks that the old thread is loaded before and after reattaching the
   existing subscription, then reads back its model and permissions. These
   observations are not a lock. Conflicts or unknown results stop the run
   without a retry. The same old thread then continues on the same server and
   its state and data root are checked. A fresh thread then reads the tracked
   `README.md` using `cat README.md` on macOS or
   `Get-Content -LiteralPath README.md` on Windows. Its real prompt, tool and
   stop Hook pairs are checked against the new definition and bundle.
   The producer saves private attempt and outcome receipts with the file digest,
   identity digest and layer version, including after a failed or uncertain
   request. The producer syncs each receipt file; on POSIX it also syncs the
   containing directory, while Windows directory durability is not established.
   A failed request is never automatically repeated.
4. `--verify-result` reads the existing output and current installed state,
   independently re-derives the evidence bindings and does not start a model
   or repeat installation. It requires the same plan and the existing output.

The producer requests a read-only sandbox and on-request approval and checks
the returned settings. Its post-turn observation checks the requested read
command and recorded tool events. Neither the sandbox setting nor the
observation log is an execution-time allowlist of files: declaring README safe
for the model does not itself prevent access to other readable files.
The reviewed Windows command display may include or omit `-NoProfile`. The
verifier still requires the known PowerShell executable wrapper and the exact
read script; this does not inspect implicit PowerShell profile activity.

## Pending states, results and limits

If the activity query's owned-process cleanup is unconfirmed, the run stops
immediately. If activity remains busy or unknown, or the trust wait expires,
inspect and retain the private batch and its journal before any further action.
The run cleans up its owned app-server when it ends; a later run cannot claim
to continue that same server or PID. A new continuity experiment may require a
new reviewed starting installation and fresh output. Do not repeat a plugin
add merely because verification or Hook review is pending.

On success, stdout reports `passed_cli_native`; `result.json` contains the
provisional CLI-native result and `independent-verification.json` binds the
independent pass to that file. A later successful `--verify-result` reports
`reverified_read_only`. Preflight reports `preflight_passed_only`. Exit code
`0` means the selected phase succeeded, `1` means a run remained pending or
failed, and `2` means inputs or verification were refused. Read the stage,
reason and retained records rather than interpreting a nonzero code as proof
that no installation occurred. Existing result files are not overwritten.

The verifier requires paired Hook events, target definition and installed
bundle parity, normal trust, old state continuity and the same server identity.
The current runtime-path witness reports `unknown`; the old task's compatible
runtime classification can be inferred only under the recorded tree and
fallback conditions, not presented as an observed operating-system path.
This evidence does not establish Desktop GUI loading or an unrelated task's
continuity. Treat source checks, CI, native results, artifact identity and
publication as separate facts.

For a failed Hook on a controlled thread and active turn, the private RPC
journal may retain a bounded diagnostic containing entry types, lengths,
digests and text-pattern classifications; it does not retain entry text.
Treat these digests as sensitive evidence. A pattern does not authenticate the
message source or establish the cause. Early events before the thread or turn
is registered may retain only metadata. A failure diagnostic never counts as
a completed Hook.
