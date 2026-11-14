# Upgrade to Context Guard 0.17.4

[简体中文](UPGRADE_0_17_4.zh-CN.md) · [Release assets](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.4)

Version 0.17.4 makes the daily-upgrade tool easier to continue after a pause. It keeps the 0.17.3 Hook and cleanup behavior. The tool comes from the source checkout at tag `v0.17.4`; it is not included in the release ZIP or installed into the plugin cache.

## Prepare the stable-entry upgrade

These steps cover an enabled 0.17.3 installation of `context-guard@codex-context-guard`. For an older version or another entry, follow the [0.17.3 upgrade guide](UPGRADE_0_17_3.md) and its linked earlier guides first, including their cleanup-setting guidance. Leave a deliberately disabled plugin disabled until you choose to enable it.

Keep the previous verified release ZIP and marketplace source. Download `context-guard-0.17.4.zip`, verify its published SHA-256, and extract it into a permanent directory that will remain the marketplace source. Obtain a source checkout at tag `v0.17.4` for the operator tool.

Follow the [daily-upgrade tool instructions](https://github.com/GreenLv/codex-context-guard/blob/v0.17.4/tools/validation/DAILY_UPGRADE.md) to prepare a private plan naming the release directory, CLI and actual Desktop executable. Run command preflight before closing Desktop. Store the plan and batch results outside the checkout and daily configuration directory.

## Switch and verify

Finish or safely hand off tasks that still need the old Hook. Official marketplace operations can remove its cache. For an existing installation, Desktop must be observed stopped before replacement. Start the prepared continuation from an external terminal. With `--resume --wait`, the tool can wait a limited time for Desktop to exit, then continue; `--wait-minutes` sets the wait limit. Follow the tool's instructions if the wait ends before Desktop exits. If no switch is needed, continue to verification without reinstalling.

Open the client and review the nine Hooks from the new installed path through CLI `/hooks`, or Desktop's **Review hooks** / **Settings > Hooks**. Continue verification with the same plan and batch. A pass identifies the installation, release files and Hooks observed by a fresh client; it does not identify what an already-running Desktop process has loaded. Confirm the version in your next Desktop task.

If the batch is interrupted, keep its records and follow the tool's recovery instructions instead of starting the installation over. If only the executable bytes changed at the same pinned path before installation began, the controlled rebind checks the host identity and signing source before making a new preparation record. Other changed inputs, a different host path, or a batch that has begun applying changes need the tool's indicated recovery or a new reviewed batch.

The stable entry and existing data root remain in use. A disabled cleanup policy, custom retention period, quarantine-only setting and durable opt-out remain effective. With no policy, sessions become eligible after 30 days and spend at least seven days in recoverable quarantine before a later automatic pass can permanently delete them. See [session storage](SESSION_STORAGE.md) for inspection, disabling and recovery commands.

Keep the previous verified ZIP/source and batch results for recovery. A downgrade is a separate official installation operation; do not copy files into a consumed cache.
