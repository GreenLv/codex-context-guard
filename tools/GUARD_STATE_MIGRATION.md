# Guard private-state inventory, migration and recovery

`tools/guard_state_migration.py` is repository tooling for moving Guard
**private task state** between installed identities on one host — for example,
from the retired 0.16.x wrapper identity's data root to the stable
`codex-context-guard` identity during a daily-entry upgrade. It is not plugin
runtime, changes no Hook, schema or installed artifact, and lives outside the
runtime-tree roots.

## What it moves and what it never moves

- Scope is `sessions-v2` session directories only, copied byte-exact under
  their encoded names. Legacy `sessions` trees are **never** migrated: they
  stay read-only under their original runtime (`retain_in_place`), and an
  active legacy task must finish under its original loaded runtime before its
  HOME's daily entry changes.
- Never read, copied, or modified: Codex auth files, `config.toml`, Hook
  trust state, plugin caches, `.locks` maintenance hints (discovery journals,
  snapshots, schedule ownership), quarantine records, tombstones, and the
  direct-interpreter `interpreter.conf`. The target runtime's own discovery
  generation finds newly arrived session names; nothing is injected.
- Migration creates no new completion facts, treats no historical message as
  current authority, and copies no credentials. Outputs contain object names,
  digests, counts and structural facts only. State is read to check its
  structure. The tool emits no requirement or prompt text. Keep its results
  on the host that owns the data.

## Stages

1. `inventory --home HOME [--home ...] --output PATH` — read-only by design:
   classifies every `plugins/data/context-guard-*` root plus the
   `<home>/context-guard` direct-command root, counts v2 and legacy sessions,
   records state schema presence, per-session tree digests, a non-blocking
   lifecycle-lock writer probe, and every same-id cross-root group whose tree
   digests differ. There is no default HOME; `~/.codex` is never assumed.
2. `plan --source-home --source-identity --target-home --target-identity
   --output PATH [--include ID ...] [--conflict-policy isolate|skip]` — builds
   the explicit migration plan. The target identity must be the stable
   `codex-context-guard`; migrating into another versioned identity is
   refused. Per-session decisions: `copy`, `idempotent_skip` (same id, same
   tree digest), `isolate` (same id, different digest — timestamps never
   decide), `excluded_unsupported_state` (missing/unreadable/unsupported
   `state.json`), `excluded_symlink` (linked entries are never followed and
   always recorded). The plan writes nothing into either data root.
3. `apply --plan PATH --workspace NEW_DIR` — copy-only execution. Apply
   takes the existing source lifecycle lock before it rechecks source bytes.
   A missing or busy lock leaves the row pending for another run. The tool
   also locks the target session before creating it exclusively. If a target
   appeared after planning, it checks for identical bytes or records a
   conflict and leaves the target in place. Planned conflicts are copied to
   `workspace/conflicts/<id>/`. Apply records each row in
   `workspace/apply-manifest.json` and cleans up a failed copy only when
   it can still identify the directory it created.
4. `verify --plan PATH --workspace DIR` — re-derives every created and
   isolated digest against the plan and manifest.
5. `summary --workspace DIR [--out NEW_PATH]` — read the saved apply and
   verify records and check them against the current copies. Use this if the
   command output was lost after a completed operation. The command leaves
   session data unchanged. An optional export path must be new, outside the
   protected data roots, and free of links.
6. `restore --workspace DIR` — keep the original plan beside the workspace
   so restore can check its digest and reconstruct the permitted paths.
   Restore locks each target session and checks its directory identity and
   contents before removing a recorded copy. If a forced process stop left
   a row in progress, restore reports that row for review and can still
   remove earlier copies with valid records.

Refused inputs exit `2`; executed rows failing close exit `1`. All stage
records stay in the workspace; prior `verify`/`restore` results rotate aside
by run time instead of being overwritten.

## Boundaries

- Inventory and plan are read-only. `apply` writes only new target session
  directories, new lifecycle lock files, and the workspace; `restore` removes
  only what its own manifest created.
- A quiescence guarantee is observational, not temporal: file age, lock-file
  absence, or an old `ended_at` never establish a safe window. The apply
  window is the pair of kernel lifecycle locks held during one session's copy.
- This tool performs no Codex-plugin installation, trust, enablement, or
  cache work; those stay with the official operations and the native upgrade
  acceptance toolkit. State copy success alone is not loaded-behavior
  evidence — the target runtime's real loading of migrated state remains a
  native acceptance fact for the consuming round.
