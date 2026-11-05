# Future stable marketplace identity

This is the upgrade contract that the 0.17.0 Unreleased source candidate
implements. The published 0.16.1 package still declares the experimental
`codex-context-guard-v016`; installed consumer wrappers and previous
acceptance evidence retain their own identities. Until the 0.17.0 line is
actually released and installed, the published runtime validator and Hook
fallbacks still enforce the experimental identity; this candidate's source
switch (marketplace manifest, validator and both Hook fallback paths) needs
its own native acceptance before release.

A future release should use the single marketplace identity
`context-guard@codex-context-guard` across subsequent versions. The next
candidate must first inspect existing ownership and registration of that name,
including historical installations, before choosing its exact transition.
A source manifest, an indexed desired identity or a disabled old entry does not
establish installation, ownership, trust, active Hook selection or migration.
Do not create a new version-named identity on every release as a substitute for
a tested upgrade path. When implementing that candidate, update its marketplace
manifest, runtime validator and both Hook fallback paths together. Verify the
actual fallback binding, not merely an unrelated matching path substring, and
include a mixed old/new path negative control.

For the first transition to the stable identity, use official operations in
disposable native macOS and Windows fixtures to establish the supported Codex
behavior. Test the transition from an existing identity and an upgrade between
two versions at the stable identity, including source/artifact parity, repeat
no-op behavior, enabled Hooks and normal trust. Record which cache paths are
removed or replaced. A previous same-identity add removed an older cache; do not
assume versioned files survive an upgrade or overwrite a consumed cache.

For that transition, exercise representative already-running and resumed tasks.
Record the loaded Hook source and private data root on each turn, compatibility
of their existing state, and late lifecycle events. A retained old cache alone
does not pin a task's runtime, and a fresh task does not prove old-task
continuity. Verify whether the host separates `PLUGIN_DATA` by identity; do not
assume that changing names transfers, merges or preserves task state or trust.
There is no general session migration command in 0.16.1. If the old task cannot
continue safely, defer that HOME's transition until dependent tasks finish or a
separately reviewed supported preservation path is available.

For the first transition, also test disabling, plugin removal and marketplace
removal in those disposable fixtures, including readback of selected and
unrelated caches, private data, registrations and settings. For later upgrades,
reuse passing evidence only when its subject and all behavior-affecting inputs
remain valid under the applicable contract; repeat the affected checks when an
identity, host mechanism, compatibility input or other relevant input changes.
Separately verify each new artifact and the installation and loaded behavior
required by that upgrade. Do not remove a real old entry while
its caches or tasks remain needed. Define recovery using retained verified
artifacts and supported host operations before changing a daily HOME; do not
assume that rerunning add restores prior caches or state. Update consumer pins
only after the corresponding upstream candidate and native transition are
accepted. Old artifact, task, source and host evidence remain distinct.
