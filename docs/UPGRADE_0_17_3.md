# Upgrade to Context Guard 0.17.3

Source candidate; publication and native acceptance are pending.

[简体中文](UPGRADE_0_17_3.zh-CN.md) · [Release assets](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.3)

Version 0.17.3 adds a maintained daily-upgrade tool for operators. The Hook behavior and cleanup settings remain those of 0.17.2. The tool is available from this version's source checkout; it is not installed into the plugin cache.

## Prepare the stable-entry upgrade

These steps cover an enabled 0.17.2 installation of `context-guard@codex-context-guard`. If you use an older version or another entry, first follow the [0.17.2 guide](UPGRADE_0_17_2.md), including its cleanup-setting guidance. Leave a deliberately disabled plugin disabled until you choose to enable it.

Save the verified previous release ZIP and marketplace source. Download and verify `context-guard-0.17.3.zip`, then extract it into a permanent directory that will remain the marketplace source. Obtain a source checkout at tag `v0.17.3` for the operator tool.

Follow the [daily-upgrade tool instructions](https://github.com/GreenLv/codex-context-guard/blob/v0.17.3/tools/validation/DAILY_UPGRADE.md) to write a private plan naming the exact release directory, CLI and Desktop executable. Run its command preflight and prepare phase before closing Desktop. Keep all results outside the checkout and daily configuration directory.

Use `--preflight-commands` then `--prepare` for the same future batch path. A standalone `--preflight` uses a separate output directory. If prepare reports `already_current`, skip apply and continue with `--verify`.

## Switch and verify

Finish or safely hand off tasks that still need the old Hook. Official marketplace operations can remove its cache. Quit Desktop before replacing that installation, then run the prepared apply command from an external terminal. If interrupted, use the same plan and batch to continue; inspect saved results before retrying.

Open your client and review the nine Hooks from the new installed path through CLI `/hooks`, or Desktop's **Review hooks** / **Settings > Hooks**. Run verify with the same plan and batch. A pass means the official installation, release files and all nine Hooks agree for a fresh client. It does not prove what an already-running Desktop process has in memory; confirm the version in your next Desktop task.

The upgrade keeps the stable identity and existing data root. A disabled cleanup policy, custom retention period, quarantine-only setting and durable opt-out remain effective. Missing-policy defaults remain 30-day eligibility followed by at least seven days in recoverable quarantine and later automatic purge. See [session storage](SESSION_STORAGE.md) for inspection, disabling and recovery commands.

Keep the previous verified ZIP/source and batch results for recovery. A downgrade is a separate official installation operation; do not copy files into a consumed cache.
