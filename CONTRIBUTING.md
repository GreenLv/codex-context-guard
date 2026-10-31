# Contributing

Thank you for helping improve Context Guard.

## Development contract

- Keep the Hook runtime free of third-party runtime dependencies.
- Add a focused regression test for every behavior change or bug fix.
- Preserve fail-closed handling for state integrity, evidence outcomes,
  supersession ambiguity, and delegated authority.
- Do not add raw prompts, transcripts, plugin-private state, credentials, local
  paths, generated caches, or private handoff artifacts to the repository.
- Do not duplicate Codex-native Plan, Goal, compaction, subagent, worktree, or
  memory controllers.
- Configure both the Git author and committer as a GitHub-provided
  `@users.noreply.github.com` address. CI audits every candidate commit while
  redacting any rejected identity value from its logs.
- A Hook definition, state schema, or observable runtime behavior change
  relative to a published release requires a plugin version change and release-note
  entry. Unpublished candidate repairs may share a version while full commits
  and runtime digests identify revisions. Use fresh isolated homes for changed
  candidate bytes; never overwrite a consumed cache.

## Validation

Routine main pushes run four full behavior lanes and two focused Windows lanes.
Release candidates and compatibility-sensitive changes use the full portability
screen. See [CI policy](docs/CI_POLICY.md) for the version table, automatic
triggers, manual commands and required release evidence. PRs retain mapped
checks; their green summary does not replace release-candidate CI.

During repair, use the selected validation plan or the owning test module.
`tools/validation/run_selected_validation.py` runs changed test modules and
their static test importers; shared fixtures, deleted tests and unknown owners
keep the full-candidate fallback. Its `--list` mode displays the selected
commands without executing them. Candidate and validation-infrastructure
changes still require the declared complete checks below.

For native acceptance, add `--preflight` to the intended command before
installation or host work. Choose an unused `--output` path outside this
repository and temporary fixtures. The entrypoint creates missing parent
directories and checks writing there before doing expensive work. A preflight
pass proves only input readiness; it creates no acceptance annex and does not
prove login, Hook trust, restricted-child access or real-model behavior.
Capture replay additionally reports its existing capture status. Run without
`--preflight` for actual acceptance; existing outputs are never replaced.
Keep original captures and results for later readback instead of rerunning
because a transfer failed.

Run the complete checks from the repository root when required:

Install validation tools with `uv==0.12.18` and
`uv sync --locked --only-group validation`. Activate the resulting virtual
environment before running checks. `uv.lock` records the resolved dependencies;
`requirements-lock.txt` is only the direct-tool index. A version change must
also refresh the project entry in `uv.lock`. CI uses `--locked` so stale locks
fail instead of being silently accepted. The Hook runtime needs no dependency
installation.

The marketplace-only candidate has no project installer or namespace installer.
Use official Codex marketplace commands only in an explicitly authorized isolated
HOME. The default versioned portable native entrypoint uses only an internally created
fresh HOME and official Codex commands. Its optional `--release-zip` consumes a
prebuilt exact artifact without rebuilding it. `--installed-plugin-root` instead
performs artifact parity and lifecycle inspection only; official installation, strict second-operation no-op,
old-cache object preservation, normal trust and real-task continuation remain
separate required gates. See `docs/INSTALLER_REMOVAL.md`.

```shell
python scripts/validate_public_repo.py .
python scripts/audit_public_tree.py .
python scripts/audit_commit_identity.py .
python scripts/run_current_behavior_suite.py
python scripts/check_phase3_transition.py
ruff check .
```

Installed lifecycle changes also require `python scripts/smoke_installed.py --plugin-root "<installed-path>"`
against the explicit isolated installed path returned by official installation and a fresh Codex task without trust
bypass.

On each clone, including Windows, configure identity at repository scope before
the first commit so a machine-level default cannot leak into public history:

```shell
git config --local user.name "Your GitHub display name"
git config --local user.email "your-account@users.noreply.github.com"
git config --local user.useConfigOnly true
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
python scripts/audit_commit_identity.py . --base origin/main --head HEAD
```

The remote CI audit is authoritative because environment variables can override
local Git configuration and local hooks are not installed automatically.

## Upstream policy

This public repository is the sole implementation upstream for Context Guard.
Product changes land and are validated here before downstream configuration
repositories update an immutable version-and-commit pin. Downstream repositories
may keep private overlays and platform acceptance records, but do not maintain a
second implementation. Contributions retain their original authorship when
integrated.
