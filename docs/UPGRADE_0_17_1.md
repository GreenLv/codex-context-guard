# Upgrade to Context Guard 0.17.1

Run `codex plugin list --json` to see the entry you use. Finish tasks that still need the old plugin before changing that entry. If you need more time, keep those tasks in a separately configured Codex environment that still loads the old version. A cache on disk does not tell you which version a task will load on its next turn.

[简体中文](UPGRADE_0_17_1.zh-CN.md) · [Release assets](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.1)

## Choose your route

| Installed version | What to do |
| --- | --- |
| **0.17.0**, `context-guard@codex-context-guard` | Upgrade in place. Save the previous marketplace source and ZIP before removing its registration. |
| **0.16.1**, public ZIP (`…@codex-context-guard-v016`) or local wrapper (`…@codex-context-guard-v0161`) | Switch to `context-guard@codex-context-guard`. Keep the differently named marketplace registered and disable its old entry before trusting the new Hooks. |
| **0.15.1**, `context-guard@codex-context-guard` | Follow the same-name upgrade steps. Keep the original 0.15.1 release source for rollback. |

Codex keeps the projects, login and model settings in your existing configuration directory. An official marketplace operation can remove a previous plugin cache. Keep a verified copy of the previous release if you may need to reinstall it.

## Install and check

1. Download `context-guard-0.17.1.zip` from the release assets and check its published SHA-256. Extract it into a directory you control and keep that directory as the marketplace source.
2. If the old marketplace is also named `codex-context-guard`, run `codex plugin marketplace remove codex-context-guard` after saving the old source. This can remove the old cache. For a switch from a differently named market, keep the old registration.
3. From the new extracted directory, run:

   ```shell
   codex plugin marketplace add .
   codex plugin add context-guard@codex-context-guard --json
   codex plugin list --json
   ```

4. Save `installedPath` from the add response. Check that the list contains one stable entry, installed and enabled at version `0.17.1`. Compare every installed file with `python3 scripts/artifact_identity.py --compare-to "<installedPath>"` from the extracted directory. On Windows, use `py -3` instead of `python3`. For an identity switch, disable the old entry through the official Plugins UI before trusting the new Hooks.
5. Open `/hooks` in a fresh Codex CLI session. Review all nine Context Guard Hooks. Once their source matches `<installedPath>/hooks/hooks.json`, trust them in the normal interface. Then start a new task in the client you normally use and confirm it loads the new version. Restart Codex Desktop if it still shows the old plugin.

## Find an older task after switching entries

An upgrade leaves Context Guard's records where they were written. A same-entry upgrade can read existing schema 13 records. When you switch entries, the new plugin uses a different data directory. For example, the 0.16.1 wrapper wrote to `plugins/data/context-guard-codex-context-guard-v0161/` beneath its Codex configuration directory.

To look up earlier records from the new entry, use the [migration tool](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md). On the same machine, it can preview and copy records in the `sessions-v2` format. It keeps the destination record if the same session has different contents there and saves the incoming copy separately. Undo removes only unchanged copies created by the selected migration run. Older `sessions` records and unsupported or unreadable records stay in place.

Pass the intended Codex configuration directories explicitly. Keep the migration workspace and results on your machine, outside Git and shared attachments. Copying records does not transfer Hook trust or move a running task.

## Recover or check a result

- To reinstall the previous version, use its verified release source with the official marketplace commands. An add by name alone may not find the old bytes. If something fails, keep the error and inspect the actual installation before taking another action.
- Ordinary file edits and tool calls continue to use Codex permissions. The opt-in cleanup command still previews by default. See [session storage and cleanup](SESSION_STORAGE.md) for policy and scheduling.
- The published ZIP passed the 0.16.1 wrapper, 0.17.0 in-place and 0.15.1 upgrade tests in isolated Codex CLI environments on macOS and Windows. [Acceptance record](LOCAL_ACCEPTANCE.md) distinguishes these checks from daily use and migration of real task data.
