# Upgrade to Context Guard 0.17.2

Run `codex plugin list --json` to find your installed entry. Finish tasks that still need the old plugin before changing it, or keep them in a separately configured Codex environment that still loads the old version. An old cache on disk does not establish which Hook an existing task will load next.

[简体中文](UPGRADE_0_17_2.zh-CN.md) · [Release assets](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.2)

## Before upgrading

Version 0.17.2 automatically maintains eligible Context Guard records when you end sessions. With no retention policy, records for sessions ended more than 30 days can move to recoverable quarantine. Later ordinary use can permanently delete them after at least seven days there. Active, unfinished, recoverable and identity-unverifiable sessions stay protected.

A disabled policy, custom retention period, quarantine-only setting, and a durable opt-out continue to apply. A damaged or unreadable policy does not authorize deletion. A missing policy uses the automatic default. If a custom quarantine-only policy is lost, the default permits permanent deletion after quarantine unless a durable opt-out is present.

Version 0.17.1 did not leave a durable record when `--maintenance-disable` removed its scheduler entry. If that is the only action you took to turn maintenance off, 0.17.2 will use the automatic default when there is no policy. To keep maintenance disabled through the upgrade, first run the command below from the 0.17.1 release directory with the data root for the intended entry. It writes an explicit disabled policy. Run the same command again from the 0.17.2 release directory to record the durable opt-out. Later upgrades respect that opt-out.

```shell
python3 scripts/context_guard.py cleanup --data-dir "/path/to/plugin-data" --policy disable
```

Run this from the extracted release directory for each version. On Windows use `py -3` instead of `python3`. To identify the data root and inspect the effective policy, follow [session storage and cleanup](SESSION_STORAGE.md#inspect-customize-or-turn-off-automatic-maintenance). If multiple entries or configuration directories exist, select the intended one before running the command.

Before switching versions, run the same command with `--policy show` in place of `--policy disable` and confirm that `enabled` is false. After disabling maintenance with 0.17.2, use `--policy show` again and check that `automatic_maintenance` reports a durable opt-out.

## Upgrade the stable entry

Use these steps for an enabled `0.17.1` installation of `context-guard@codex-context-guard`. If you use an older version or another entry, first follow the [0.17.1 upgrade guide](UPGRADE_0_17_1.md). Verify the stable entry and its data root, then return here to update to 0.17.2. If you want the plugin to stay disabled, leave it disabled and postpone this upgrade procedure, which enables the new installation.

1. Save the existing 0.17.1 marketplace source and verified release ZIP. Download `context-guard-0.17.2.zip` from the release assets, verify its published SHA-256, and extract it into a directory you control. Keep that directory as the new marketplace source.
2. After saving the old source, run `codex plugin marketplace remove codex-context-guard`. This can remove the old plugin cache.
3. From the new extracted directory, run:

   ```shell
   codex plugin marketplace add .
   codex plugin add context-guard@codex-context-guard --json
   codex plugin list --json
   ```

4. Save `installedPath` from the add response. Check the list for one enabled stable entry at version `0.17.2` that points to the new marketplace source. From the extracted directory, compare the installed files with `python3 scripts/artifact_identity.py --compare-to "<installedPath>"`. On Windows, use `py -3` instead of `python3`.
5. In a fresh Codex CLI task, open `/hooks` and inspect the nine Context Guard Hook sources. When they match `<installedPath>/hooks/hooks.json`, use the normal interface to review and trust them. Check the loaded version in a fresh task in the client you use. Codex Desktop may need a restart to load the new entry.

A same-entry upgrade leaves the existing task records in their data root. It does not guarantee an already-running task keeps its previous Hook. Reinstalling an older version requires its verified release source and official marketplace operations. If an operation fails, preserve its result and inspect the actual installation before retrying. See [session storage](SESSION_STORAGE.md) and [compatibility](COMPATIBILITY.md) for details.
