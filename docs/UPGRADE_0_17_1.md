# Upgrading to 0.17.1

First identify the Context Guard entry your Codex installation uses. Finish
work that still needs the old runtime, then follow the matching route below.
Download the official ZIP for your installation from the release assets.
[GitHub Release](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.1)

Also read this guide in
[Simplified Chinese](UPGRADE_0_17_1.zh-CN.md).

## Who this upgrade concerns

- **0.16.1 users**: the public ZIP uses `context-guard@codex-context-guard-v016`.
  A local marketplace wrapper can install the same bytes as
  `context-guard@codex-context-guard-v0161`. Check which entry your host uses.
  Both routes lead to `context-guard@codex-context-guard` in 0.17.1.
- **0.17.0 stable-identity users**: 0.17.1 is an in-place upgrade under the
  same identity.
- **0.15.1 users**: the historical route remains covered by its declared
  contract; the same steps apply, with the 0.15.1 release as the starting
  point.

## Your daily entry

Your daily Codex Desktop/CLI HOME keeps its own configuration. The upgrade
changes which plugin version that HOME loads — through official Codex
marketplace operations only. It does not change your projects, login, or
model settings, and it does not modify any versioned plugin cache by hand.

## Old tasks first

Before changing a HOME's plugin:

1. Finish tasks that still need the old runtime, or keep them in a separately
   configured HOME that stays on the old version. Do not delete or hand-edit
   any versioned cache to "keep" an old runtime.
2. An official same-name or identity-switch operation may remove an old
   cache. Keeping cache bytes on disk never proves which Hook an old task
   loads; a retained cache is not a migration.
3. Legacy `sessions` trees (pre-0.15.0) are never migrated by this product.
   Continue such a task under its original loaded runtime until it finishes.

## Moving private task state

Installing 0.17.1 leaves private sessions in the data directory of the
identity that wrote them. For the 0.16.1 wrapper, that directory is
`plugins/data/context-guard-codex-context-guard-v0161/`. The stable identity
uses a different directory and needs the migration below to find that state.

If you want your old sessions visible under the stable identity's data root
(for example, so recovery and status queries find them after the daily
cutover), use the repository migration tool
([documentation](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md)):

- It is read-only by default. `inventory` and `plan` never write state.
- `apply` copies sessions byte-exact into the target data root while holding
  the runtime's own lifecycle locks; an existing target session is never
  overwritten. A session that exists on both sides with different content is
  isolated outside the data root for a manual decision — timestamps never
  decide.
- `verify` re-checks every copied digest; `restore` removes exactly what one
  apply run created, refusing anything that changed after the copy.
- Pre-0.15.0 legacy sessions and unreadable/unsupported state files are
  reported and left in place.

Run the tool with an explicit HOME, outside the repository, and keep its
workspace and results on your host; private state never belongs in Git or
attachments.

## Upgrade in your current HOME

1. Download `context-guard-0.17.1.zip` from the release assets and verify its
   SHA-256 against the published digest. Extract it in a directory you control
   and keep that directory as the marketplace source.
2. Run `codex plugin list --json` to identify the current entry and confirm
   that tasks requiring the old runtime have finished. If you are upgrading
   within the stable identity, save the old marketplace source and its ZIP,
   then remove the old registration with
   `codex plugin marketplace remove codex-context-guard`. This can remove
   the old version cache. For a switch from a differently named market,
   keep the old registration.
3. From the new extracted directory, run these commands. Save the add
   response so you can use its `installedPath` in the next step.

   ```shell
   codex plugin marketplace add .
   codex plugin add context-guard@codex-context-guard --json
   codex plugin list --json
   ```

4. Check that the stable entry is installed and enabled at version `0.17.1`.
   Compare the release files with `installedPath` using
   `python3 scripts/artifact_identity.py --compare-to "<installedPath>"`
   (`py -3` on Windows). For an identity switch, disable only the old
   entry through the official Plugins UI before trusting the new Hooks.
5. Open `/hooks` in a fresh Codex CLI session. Review the nine Hooks from
   the new cache through the normal interface. In the entry you actually
   use, run a fresh task that triggers the Hooks and check that it loads
   the new version. Restart Codex Desktop if it still shows the old
   plugin after the switch.

## What to expect

- Schema 13 state written by 0.14–0.17.0 is read without migration; pending
  requirements, waits, evidence and recovery behavior are unchanged.
- The default business-tool path stays approval-free; no new approvals are
  introduced by the upgrade.
- Retention maintenance stays opt-in: preview by default, deletion only with
  an explicitly enabled policy.

## Recovery

- Before the daily cutover, keep the verified old plugin artifact (ZIP with
  digest) and your previous registration/entry notes. A same-identity
  upgrade may have removed the old cache, so restoring means re-running the
  official installation with the old artifact — re-adding by name alone is
  not assumed to restore it.
- The migration tool's `restore` undoes a state migration exactly; unrelated
  sessions and any session that changed after the copy are never removed.
- If anything fails, keep the original failure records; do not repair a
  consumed cache in place.

## Implementation notes

The [native upgrade toolkit](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/validation/NATIVE_UPGRADE_ACCEPTANCE.md)
records the versions, package hashes and tool commit used on each host. The
[migration tool reference](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md) explains the
copy, conflict and recovery checks. The acceptance record separates native
checks, exact artifacts, CI and publication. [Acceptance record](LOCAL_ACCEPTANCE.md)
