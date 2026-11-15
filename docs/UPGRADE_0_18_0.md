# Upgrade to Context Guard 0.18.0

[简体中文](UPGRADE_0_18_0.zh-CN.md) · [Release assets](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.18.0)

The optional between-turns route is intended for an existing 0.17.3 stable-entry installation, `context-guard@codex-context-guard`, when the tool confirms that the old and new runtimes are compatible. The operator tool comes from the `v0.18.0` source checkout, outside the release ZIP and plugin cache.

## Prepare

Keep the verified previous release ZIP and its marketplace source. Download `context-guard-0.18.0.zip`, verify its published SHA-256, and extract it into a directory you control and retain as the marketplace source. Obtain the operator tool separately from the `v0.18.0` source checkout. Follow the [daily upgrade instructions](https://github.com/GreenLv/codex-context-guard/blob/v0.18.0/tools/validation/DAILY_UPGRADE.md) to make a private plan and result directory outside the checkout and daily configuration directory. The between-turns plan names the retained verified old artifact as well as the new one. Run command preflight and prepare first.

The tool compares the installed old files with the retained old artifact and checks the new runtime. If compatibility, ownership or another prerequisite cannot be established, follow the refusal; do not use the between-turns route. If your plugin is deliberately disabled, keep it disabled until you choose to enable it. For an earlier installation or another entry, follow the [0.17.3 guide](UPGRADE_0_17_3.md) and its earlier guides, including their cleanup-setting instructions.

## Make a between-turns plan

Create a private plan file outside the source checkout and daily Codex configuration. Replace every example path below with an absolute path on your machine: the target and retained old release directories, an existing working directory, the actual Desktop host executable, and the selected Codex CLI executable. On macOS the actual host can be inside ChatGPT.app; use its real executable, not just the app directory. Do not copy a path from another machine. The target and old directories must contain their complete verified release files.

For macOS/POSIX, a complete plan has this shape:

```json
{
  "schema": "cg-daily-upgrade-plan/v2",
  "transition_strategy": "between-turns",
  "entry": "context-guard@codex-context-guard",
  "marketplace": "codex-context-guard",
  "target_version": "0.18.0",
  "artifact_dir": "/absolute/path/to/extracted-0.18.0",
  "old_artifact_dir": "/absolute/path/to/verified-0.17.3",
  "cwd": "/absolute/path/to/existing/work-directory",
  "desktop_executable": "/absolute/path/to/actual/Codex-Desktop-executable",
  "cli": "/absolute/path/to/codex",
  "sandbox_markers": [],
  "drain_seconds": 120
}
```

For Windows, use your own absolute paths; JSON accepts forward slashes:

```json
{
  "schema": "cg-daily-upgrade-plan/v2",
  "transition_strategy": "between-turns",
  "entry": "context-guard@codex-context-guard",
  "marketplace": "codex-context-guard",
  "target_version": "0.18.0",
  "artifact_dir": "C:/Path/To/extracted-0.18.0",
  "old_artifact_dir": "C:/Path/To/verified-0.17.3",
  "cwd": "C:/Path/To/existing-work-directory",
  "desktop_executable": "C:/Path/To/actual/Codex-Desktop.exe",
  "cli": "C:/Path/To/codex.exe",
  "sandbox_markers": [],
  "drain_seconds": 120
}
```

`sandbox_markers` may stay empty when no sandbox helper identity has been verified. `drain_seconds` sets the bounded activity wait from 1 to 900 seconds; 120 is the default. An optional `data_dir` may name the existing plugin data directory by absolute path for a read-only cleanup-policy observation; omitting it does not change the policy. No setting or path in these examples should be added to the public checkout.

Choose an existing owner-private results **parent** outside the checkout, daily Codex configuration and target release directory. In the commands below, `batch-0180` is a **new, nonexistent child** of that parent: do not create the child yourself. `--preflight-commands` checks its parent and does not create the batch; `--prepare` creates it and saves the preparation. Use the same private plan and batch throughout. In the commands, replace the sample paths with the same paths you selected above and run the launcher from the `v0.18.0` source checkout. Continue to the next step only when the preceding command succeeds.

### macOS/POSIX shell

```sh
cd "/absolute/path/to/source-checkout"
plan="/absolute/path/to/private-plan.json"
batch="/absolute/path/to/private-results/batch-0180"
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --preflight-commands &&
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --prepare
```

After a successful preparation, wait until the current Codex turn ends. Pause starting new operations and keep that pause through the switch. Then run:

```sh
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --resume
```

### Windows PowerShell 5.1 or 7

```powershell
Set-Location -LiteralPath 'C:\Path\To\SourceCheckout'
$plan = 'C:\Path\To\PrivatePlan.json'
$batch = 'C:\Path\To\PrivateResults\batch-0180'
$entry = '.\tools\validation\run_daily_upgrade.ps1'
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--preflight-commands')
if ($LASTEXITCODE -ne 0) { throw 'Command preflight did not succeed' }
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--prepare')
if ($LASTEXITCODE -ne 0) { throw 'Preparation did not succeed' }
```

After a successful preparation, wait until the current Codex turn ends. Pause starting new operations and keep that pause through the switch. Then run:

```powershell
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--resume')
```

`--resume` applies the prepared switch when needed and runs verification. If it reports that Hook review is pending, review the new Hooks through CLI `/hooks` or the client’s official Hook review interface, then run the same `--resume` command again with the same plan and batch. If activity is busy or unknown, or another condition is pending or refused, inspect the message and retained records before retrying; an exit code of 1 or 2 does not prove that no installation step occurred. Do not start a new turn during an unfinished switch. Resume the old task only after verification reports `passed` and the command exits 0. The v2 route does not use `--wait`; that option belongs to the stopped-host v1 route.

## Switch between turns

Wait for the current turn to finish, then pause starting new operations. Keep Codex open while the prepared tool waits for old runtime activity to finish and performs the official marketplace and plugin operations. Do not start a new turn until the switch has finished. The official plugin add may remove the old cache; the tool does not copy files into or repair a consumed cache. If the batch stops, keep the same plan and records and follow its continuation message.

The stopped-host route remains available. Its `--resume --wait` option waits a bounded time for the host to exit; it does not apply to the between-turns plan. If no switch is needed, continue to verification without reinstalling.

## Review and verify

Review the new Hooks through the normal official interface if requested, then continue verification. Resume the existing task after verification passes. A fresh CLI client's inventory reports which Hook definitions that client sees; it does not by itself show that an old task continued or that the Desktop GUI loaded those Hooks. Actual task execution and GUI behavior need separate observations.

The stable plugin identity and existing data root remain in use. A disabled cleanup policy, custom retention period, quarantine-only setting and durable opt-out remain effective. With no policy, sessions become eligible after 30 days and spend at least seven days in recoverable quarantine before a later automatic pass can permanently delete them. See [session storage](SESSION_STORAGE.md) for inspection, disabling and recovery commands. Keep the old verified release and batch records for recovery; a downgrade is a separate official installation operation.
