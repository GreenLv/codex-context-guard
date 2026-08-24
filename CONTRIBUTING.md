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
  requires a plugin version change and release-note entry.

## Validation

Run from the repository root:

```shell
python scripts/validate_public_repo.py .
python scripts/audit_public_tree.py .
python scripts/audit_commit_identity.py .
python -m unittest discover -s tests -p "test_*.py"
ruff check .
```

Installed lifecycle changes also require `python scripts/smoke_installed.py`
against an isolated installed cache and a fresh Codex task without trust
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
