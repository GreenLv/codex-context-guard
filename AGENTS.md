# Context Guard repository instructions

These instructions apply to every agent working in this repository, regardless
of model or client. User instructions and platform approval boundaries remain
authoritative.

## Project contract

- This repository is the standalone public Context Guard product: a local
  correctness sidecar for Codex long-running tasks. It complements rather than
  replaces Codex Plan, Goal, compaction, subagent, worktree, transcript, or
  memory behavior.
- Keep the Hook runtime dependency-free beyond the Python standard library and
  compatible with Python 3.10 or newer.
- Preserve fail-closed behavior for integrity, private control, evidence,
  supersession, scope, path, archive, and delegated-authority failures.
- Do not claim that Context Guard is a security sandbox, arbitrary semantic
  verifier, or universal visual-understanding system. Unsupported deterministic
  verification remains visible as `legacy_fallback`.
- Treat implementation, execution, generated artifacts, installed state,
  native-platform acceptance, CI, tags, and releases as separate facts.

## Repository and privacy boundaries

- This public product and the maintainer's private configuration product are
  sibling products with selected shared-core files, not a public generated tree
  and not an automatic bidirectional mirror.
- The public shared core comprises the state schema, Hook definitions, runtime,
  runtime regression tests, Context Guard Skill, Skill UI metadata, and
  successor-pack reference. Keep exact sibling parity when a change touches one
  of these files, using the private maintainer repository's read-only parity
  checker when that repository is available.
- Public-owned packaging, installer, documentation, governance, CI, marketplace
  metadata, release notes, and release history remain independently reviewed.
  Never overwrite them wholesale from a sibling repository.
- Never commit raw prompts, transcripts, plugin-private state, proof manifests,
  credentials, tokens, private handoffs, local paths, user identifiers, runtime
  caches, archives, generated files, or binary filesystem metadata.
- Run the tracked-tree privacy audit before publication. A clean worktree alone
  is not privacy evidence.

## Before changing code

- Read `CONTRIBUTING.md` for the development contract.
- Read `docs/ARCHITECTURE.md` before changing runtime, Hook, state, recovery,
  evidence, or Stop behavior.
- Read `docs/VERSIONING.md` before changing observable runtime bytes, protocol
  constants, schema, manifests, or version numbers.
- Read `docs/PRIVACY.md` before changing persisted fields, exports, diagnostics,
  logs, attachments, or redaction.
- Read `docs/COMPATIBILITY.md` and `docs/LOCAL_ACCEPTANCE.md` before changing a
  compatibility, platform, validation, or release claim.
- Inspect the exact diff and existing tests before editing. Preserve unrelated
  user changes and do not clean or rewrite an existing worktree implicitly.

## Implementation and versioning

- Add focused positive, negative, and adversarial regression coverage for every
  behavior change or bug fix. Prefer a regression that fails on the old code.
- Keep all eight Hook events and both POSIX and Windows command forms aligned
  unless an intentional versioned contract change says otherwise.
- A Hook definition, state schema, observable behavior, shared runtime byte, or
  installed lifecycle change requires a new plugin version and release-note
  entry. Keep `pyproject.toml`, `.codex-plugin/plugin.json`, validator constants,
  protocol documentation, and compatibility claims consistent.
- Installed versioned plugin caches are immutable. Never refresh or repair an
  already consumed version from new source bytes. Advance the patch version and
  preserve old caches for open tasks.
- Use the safe installer for cache and archive operations. Do not hand-copy into
  a live cache, delete historical caches automatically, or treat an unindexed or
  hash-mismatched archive as repair authority.
- Keep public author and committer identities on GitHub-provided noreply
  addresses. Never print rejected identity values or other credentials.

## Documentation

- Keep English and Simplified Chinese README behavior, diagrams, examples,
  version status, and compatibility claims synchronized.
- Treat README, CHANGELOG, and the GitHub Release body as bilingual adopter
  surfaces. Keep separate English and Simplified Chinese changelog files with
  matching version/date structure, and publish one release body with English
  first and Chinese second. Keep detailed architecture, privacy, compatibility,
  and acceptance evidence in one authoritative language unless the project
  explicitly adopts a complete translated evidence set.
- Keep quick-start material concise. Put protocol history in
  `docs/VERSIONING.md`, compatibility boundaries in `docs/COMPATIBILITY.md`,
  and concrete acceptance evidence in `docs/LOCAL_ACCEPTANCE.md`.
- Evidence statements must name their boundary. Do not infer native Windows
  from CI, native macOS from Windows, installed behavior from source tests, or
  public acceptance from a private sibling result.
- Update tests when a stable public documentation contract changes; do not add
  brittle assertions for incidental prose.

## Changelog and release writing

- Write for adopters, not as a commit transcript. Lead with the user-visible
  outcome and explain internals only when they affect behavior, compatibility,
  security, installation, or operation.
- Keep releases newest first. Each release uses `Highlights`, `Changes`, and
  `Validation` in that order. Put three to five highlights in descending
  importance: correctness or safety first, then compatibility and operations,
  then maintenance. Do not give every change equal weight.
- Keep `Validation` compact and evidence-bounded. Distinguish native macOS,
  native Windows, CI, HOL, installation, tag, and GitHub Release evidence; one
  does not substitute for another.
- Fold unpublished intermediate candidates into the next release's history.
  Identify consumed versions explicitly, but do not present them as releases.
- While a version is not published, label it `Unreleased` or `source candidate`
  everywhere. A release commit replaces those labels with the version and ISO
  date and updates every `latest published` reference consistently.
- Derive the GitHub Release body from that version's changelog entry. Start
  with the same outcome-focused highlights, include only material upgrade or
  compatibility notes, and end with a link to the full changelog. Do not use an
  automatically generated raw commit list as the primary release narrative.

## Validation matrix

- Use a verified Python 3.10+ interpreter; do not assume the operating system's
  default `python3` is new enough. Shell scripts must state whether they target
  POSIX shell, `bash`, PowerShell, or another runtime.
- For documentation-only changes, run the affected contract tests, repository
  validator, privacy audit, and `git diff --check`.
- For runtime or release changes, run at least:

```shell
python scripts/validate_public_repo.py .
python scripts/audit_public_tree.py .
python -m unittest discover -s tests -p "test_*.py"
python scripts/context_guard.py self-test
ruff check .
python -m compileall -q scripts tests
git diff --check
```

- Installer, cache, archive, or lifecycle changes also require an isolated
  `--codex-home` install, a strict second no-op, source/cache parity, and
  `scripts/smoke_installed.py` against the installed plugin root. Use a fresh
  Codex task without trust bypass when the observable trusted-Hook lifecycle is
  in scope.
- Validate public/private shared-core parity when shared files change. Record
  capability-aware platform skips precisely; never turn a skip into a pass.
- Ensure validation commands propagate the first real failure. After a failure,
  classify it and change a relevant variable before retrying.

## Git and release sequence

- Preserve unrelated worktree changes. Keep commits narrow, review staged paths,
  run `git diff --cached --check`, and verify the exact author and committer
  identity before pushing.
- Do not rewrite published history, move an existing release tag, or overwrite a
  consumed cache. Tags are annotated and must point to the exact validated
  release commit.
- Release in this order:

1. Freeze the exact version and commit; verify clean public/private boundaries
   and shared-core parity.
2. Pass local source, test, lint, compile, audit, isolated install/lifecycle,
   and required native-platform gates for that exact source.
3. Push `main`, then require green main CI and HOL for the release commit.
4. Create and push an annotated `vX.Y.Z` tag pointing to that same commit.
5. Require green tag CI, create a non-draft, non-prerelease GitHub Release, and
   read back the tag target, release metadata, published notes, and clean local
   state.

Do not tag or publish while any required exact-source gate is pending or while
documentation still describes the version as an unreleased candidate.
