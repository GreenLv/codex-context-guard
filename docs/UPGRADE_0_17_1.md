# Upgrading to 0.17.1

This guide covers the 0.17.1 maintenance upgrade for existing users. It
explains what changes in your daily entry, what happens to old tasks and
private state, what you must do, what to expect, and how to recover — before
any implementation detail. Public availability of 0.17.1 is determined by the
[GitHub Releases](https://github.com/GreenLv/codex-context-guard/releases)
readback; until then this version is a source candidate.

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
([documentation](../tools/GUARD_STATE_MIGRATION.md)):

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

## What you must do

1. Read back the release assets and verify the ZIP digest published with the
   release.
2. Use official marketplace operations in your HOME (register the stable
   marketplace source, `codex plugin add`, normal enablement). Never register
   a Git checkout or a hand-copied cache.
3. Review Hook trust normally when the host asks — there is no custom
   approval string, no re-login, and no trust bypass in this upgrade.
4. After installation, check the loaded state: the plugin row for
   `context-guard@codex-context-guard` with the new version, all nine Hooks
   enabled and trusted, and your ordinary tasks still running. A real task
   that triggers Hooks is the only loaded-behavior evidence.

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

The [native upgrade toolkit](../tools/validation/NATIVE_UPGRADE_ACCEPTANCE.md)
records the versions, package hashes and tool commit used on each host. The
[migration tool reference](../tools/GUARD_STATE_MIGRATION.md) explains the
copy, conflict and recovery checks. Native macOS and Windows acceptance,
CI, the HOL plugin scan and publication are pending for this candidate.
