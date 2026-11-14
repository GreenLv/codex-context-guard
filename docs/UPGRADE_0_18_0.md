# Upgrade to Context Guard 0.18.0 — source candidate

[简体中文](UPGRADE_0_18_0.zh-CN.md) · [Daily upgrade tool](../tools/validation/DAILY_UPGRADE.md)

Version 0.18.0 is an unreleased source candidate. Its optional between-turns route is intended for an existing 0.17.3 stable-entry installation, `context-guard@codex-context-guard`, when the tool confirms that the old and new runtimes are compatible. The operator tool is in the source checkout, outside the release ZIP and plugin cache. The candidate has not yet been published; do not treat a future tag or download as available.

## Prepare

Keep the verified previous release ZIP and its marketplace source. Prepare a reviewed 0.18.0 candidate artifact directory and the matching source-checkout tool. Follow the [daily upgrade instructions](../tools/validation/DAILY_UPGRADE.md) to make a private plan and result directory outside the checkout and daily configuration directory. The between-turns plan names the retained verified old artifact as well as the new one. Run command preflight and prepare first.

The tool compares the installed old files with the retained old artifact and checks the new runtime. If compatibility, ownership or another prerequisite cannot be established, follow the refusal; do not use the between-turns route. If your plugin is deliberately disabled, keep it disabled until you choose to enable it. For an earlier installation or another entry, follow the [0.17.3 guide](UPGRADE_0_17_3.md) and its earlier guides, including their cleanup-setting instructions.

## Switch between turns

Wait for the current turn to finish, then pause starting new operations. Keep Codex open while the prepared tool waits for old runtime activity to finish and performs the official marketplace and plugin operations. Do not start a new turn until the switch has finished. The official plugin add may remove the old cache; the tool does not copy files into or repair a consumed cache. If the batch stops, keep the same plan and records and follow its continuation message.

The stopped-host route remains available. Its `--resume --wait` option waits a bounded time for the host to exit; it does not apply to the between-turns plan. If no switch is needed, continue to verification without reinstalling.

## Review and verify

Review the new Hooks through the normal official interface if requested, then continue verification and resume the existing task. A fresh CLI client's inventory reports which Hook definitions that client sees; it does not by itself show that an old task continued or that the Desktop GUI loaded those Hooks. Actual task execution and GUI behavior need separate observations.

The stable plugin identity and existing data root remain in use. A disabled cleanup policy, custom retention period, quarantine-only setting and durable opt-out remain effective. With no policy, sessions become eligible after 30 days and spend at least seven days in recoverable quarantine before a later automatic pass can permanently delete them. See [session storage](SESSION_STORAGE.md) for inspection, disabling and recovery commands. Keep the old verified release and batch records for recovery; a downgrade is a separate official installation operation.
