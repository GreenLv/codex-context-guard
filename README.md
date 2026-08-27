# Context Guard

[![CI](https://github.com/GreenLv/codex-context-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/GreenLv/codex-context-guard/actions/workflows/ci.yml)
[![HOL Plugin Scanner](https://github.com/GreenLv/codex-context-guard/actions/workflows/hol-plugin-scanner.yml/badge.svg)](https://github.com/GreenLv/codex-context-guard/actions/workflows/hol-plugin-scanner.yml)
[![Release](https://img.shields.io/github/v/release/GreenLv/codex-context-guard)](https://github.com/GreenLv/codex-context-guard/releases)
[![License](https://img.shields.io/github/license/GreenLv/codex-context-guard)](LICENSE)

[简体中文](README.zh-CN.md) | [Introduction](https://greenlv.github.io/blogs/protecting-context-in-long-running-agent-tasks/) | [Changelog](CHANGELOG.md)

Context Guard keeps important requirements from disappearing during a long Codex task. It restores a private checklist after compaction or resume and requires successful evidence before the task can be reported complete.

It works beside Codex Plan, Goal, memories, subagents, worktrees, and the transcript; it does not replace or control them.

> Release status: `0.8.12` is the latest published release. See the [changelog](CHANGELOG.md), [compatibility matrix](docs/COMPATIBILITY.md), and [local acceptance record](docs/LOCAL_ACCEPTANCE.md).

The current checkout contains the unreleased `0.9.1` source candidate. The
published `0.8.12` release and consumed `0.9.0` candidate caches remain
immutable.

## Install

Requirements: Python 3.10 or newer, Codex CLI `0.146.0` or newer as the tested minimum, and a Codex surface that loads plugins and lifecycle Hooks.

Version 0.8.8 selects a supported Python interpreter for Hook execution instead
of assuming the first `python3` on `PATH` is new enough. This matters on macOS
hosts where `/usr/bin/python3` can still be 3.9.

Version 0.8.11 additionally keeps Hooks working when a host prunes historical
versioned caches while a fresh task starts: each command prefers the task's
trusted plugin root and falls back to the newest surviving Context Guard tree
under the managed plugin cache, failing closed with a reinstall hint otherwise.

The 0.9.1 source candidate advances to Stop protocol 2.0.0: only an
authenticated full-coverage checkpoint can mark a task complete. Completion
wording remains visible in diagnostics but cannot alter the authoritative Stop
outcome, pending state, or continuation count. Privacy, integrity, invalid
control, and explicit user-persistence failures remain hard gates. It also
replaces the consumed 0.9.0 candidate's POSIX-only incident-corpus permission
check with a fail-closed native Windows ACL contract.

```shell
git clone https://github.com/GreenLv/codex-context-guard.git
cd codex-context-guard
python3 scripts/manage_plugin.py --apply
```

On Windows:

```powershell
py -3.10 scripts\manage_plugin.py --apply
```

The installer registers the repository marketplace, installs `context-guard@codex-context-guard`, checks source/cache parity, and keeps hash-indexed archives for tasks that still use an older Hook path.

Installing a plugin does not trust its Hooks automatically. Start a fresh Codex task, open `/hooks`, inspect all eight definitions, and trust them only when they match this repository. Start another fresh task after installation or Hook changes.

## Try it

In a fresh task, activate Context Guard:

```text
$context-guard
```

Then inspect the protected state:

```text
context-guard status
context-guard diagnose
```

For a recovery check, use it on a non-trivial synthetic task, run `/compact`, and confirm that the same open requirements return immediately afterward.

## What it protects

- Requirements, acceptance criteria, prohibitions, and later corrections keep stable task-local identities.
- Compaction and resume restore the open checklist instead of relying only on a conversational summary.
- Successful tool evidence must match the required subject and surface before it can close an item.
- Images and other multimodal inputs keep only hashes and bounded metadata. When the user asks for an image change, completion evidence can be tied to an inspection of the changed image rather than merely to a successful tool call.
- Ambiguous output remains `unknown`; damaged or unverifiable private state fails closed.
- Exports are explicit and redacted. Image bytes, credentials, and raw transcript content are not copied into the requirement ledger.

Proof protocol 1.0.0 checks only obligations that follow clearly from the user's request: for example, whether evidence belongs to the named file or URL, whether an edited image was inspected, or whether every explicitly listed object was covered. Cases without that kind of deterministic check use the earlier completion behavior (internally named `legacy_fallback`) rather than pretending to understand arbitrary semantics or pixels. Stop protocol 2.0.0 keeps completion checkpoint-authoritative and turn-bound: natural-language completion classification is diagnostic only, and an unfinished disposition is advisory only and cannot force a new turn.

## How 0.8.3 separates different sources

Version 0.8.3 no longer treats user instructions, repository guidance, Skills, Codex Plan, and tool results as interchangeable text. After a project execution contract is adopted, it records what each source is allowed to decide in this order:

| Source | What it decides in a task |
| --- | --- |
| System, sandbox, platform permissions, and Hook trust | These are hard boundaries; lower sources cannot override them. |
| The user who started the task | Defines the goal and which writes are allowed or prohibited. A Skill or Codex Plan cannot expand this authority. |
| Repository `AGENTS.md` and selected Skills | Define the adopted workflow and safety checks, but cannot authorize a push, release, or installation by themselves. |
| Codex Plan | Describes the model's current, revisable execution steps. Context Guard keeps only a read-only mirror and optional binding; it does not edit the plan. |
| Tool, file, image, UI, and public-readback evidence | Establishes facts such as whether a file changed, an image was inspected, or a page is public. A successful result cannot create user authority. |

For example, suppose the user asks Codex to follow a publishing Skill and update an article with a cover image. Context Guard can record which Skill was adopted, the current execution phase, and an optional Codex Plan binding; image protection can bind the cover image and its edited readback to the exact object. If the Skill or Plan later changes, the old binding is marked for review. Merely installing the Skill, adding “publish” to the model plan, or receiving a successful tool result does not replace user authorization.

Version 0.8.3 records and restores these relationships and reports drift during completion checks. It does not add a `PreToolUse` Hook or intercept an operation before the tool runs.

## How it works

```mermaid
flowchart TB
  A["You give Codex a task<br/>requirements · prohibitions · acceptance checks"]
  B["Context Guard keeps a private checklist<br/>and records later corrections"]
  C["Codex works normally<br/>files · tools · tests · subagents"]
  D["After /compact or resume<br/>the open checklist is restored"]
  E{"Does every open item have<br/>matching successful evidence?"}
  F["No · continue work<br/>or report the blocker"]
  G["Yes · allow normal completion"]

  A --> B --> C --> D --> E
  E -->|No| F
  E -->|Yes| G
```

Codex still owns the work and its native planning state. Context Guard carries the bounded correctness checklist across context boundaries; after an explicit 0.8.3 project adoption, it also restores the adopted instruction sources, unfinished phases, and plan-drift state before checking a completion claim.

## Everyday example: write a technical design document without losing decisions

Suppose the task is:

```text
Write docs/design/checkout-v2.md.

- Keep the approved API and data-flow decisions unchanged.
- Do not change the rollout date or add infrastructure commitments.
- Follow the RFC template.
- Give every recommendation a source link or a "to verify" label.
```

After research, edits, diagrams, and `/compact`, Context Guard restores those same items. A passing Markdown check cannot close the whole task: the approved decisions, RFC template, source links, and prohibited commitments each still need matching evidence.

This example explains the contract boundary; it does not claim that Context Guard can decide whether the design itself is sound.

## What you may see in a guarded task

| ID | Meaning |
| --- | --- |
| `R001` | A requirement captured for this task. |
| `A003` | An acceptance item checked independently. |
| `E####` | A successful evidence record that may close a compatible item. |

These are task-local identifiers, not GitHub issues or global task numbers. They may appear in progress text but the private ledger is not printed in the final reply.

## When Context Guard asks Codex to continue

When an open requirement still lacks matching evidence, Context Guard may ask Codex to continue with this standard redacted message:

```text
[Context Guard continuation] The task is not yet safely complete.
```

The message is normal when requested work is still open. It is a warning sign, not proof of a bug: if the task appears complete, ask Codex what remains and run `context-guard status` or `context-guard diagnose` to see which bounded condition triggered it. Earlier versions did sometimes misread quoted completion text as `whole_completion_without_checkpoint` or confuse a user handoff with assistant-owned work; reports of surprising continuation messages led to several classifier fixes. The current protocol yields safely when work is waiting for the user, an external result, or an explicit deferral.

An active task can also keep an old immutable Hook path after an upgrade. That is a separate installation-lifecycle problem; its diagnostic form is:

```text
python3: can't open file '.../context-guard/0.7.3/scripts/context_guard.py'
```

Start a fresh task after upgrades; do not overwrite a consumed versioned cache. See [Versioning](docs/VERSIONING.md) for the lifecycle contract.

## User controls

| Command | Purpose |
| --- | --- |
| `$context-guard` or `context-guard on` | Activate recovery and completion gating. |
| `context-guard off` | Disable gating while preserving prompt journaling. |
| `context-guard status` | Show protected-state counts without raw prompts. |
| `context-guard diagnose` | Show bounded diagnostics without raw prompts or replies. |
| `context-guard export <path>` | Write an explicit redacted handoff in the current project. |
| `context-guard rollover <directory>` | Validate prepared successor input and write a non-overwriting handoff plus hash manifest. |

Read [Successor Pack Input](skills/context-guard/references/successor-pack.md) before using `rollover`. It never creates or authorizes another task.

## Private data and retention

Runtime data is stored under Codex-managed `PLUGIN_DATA`. Prompt bodies, task state, evidence summaries, and recovery files remain local runtime data and are not part of this repository.

Ended sessions are eligible for cleanup after 30 days. Redacted exports are created only when requested and omit raw prompts, transcripts, credentials, authorization headers, URL query values, and plugin-private paths. See [Privacy](docs/PRIVACY.md).

## Observed token overhead

In a small anonymized sample of five completed tool-heavy desktop tasks on 0.6.1, direct Hook/recovery context was about 1.4% of total tokens; including plugin-triggered checks brought the observation to about 1.5%. Treat about 1%–2% as an order-of-magnitude estimate for similar tasks, not a guarantee.

## Update and uninstall

```shell
git pull --ff-only
python3 scripts/manage_plugin.py --apply
```

Plugin source changes require a version bump. Historical caches and trusted archives remain available to tasks that already loaded them.

```shell
codex plugin remove context-guard@codex-context-guard
codex plugin marketplace remove codex-context-guard
```

Removing code does not remove private runtime data. Keep old data or caches while an active task may still depend on them.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Privacy](docs/PRIVACY.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Versioning](docs/VERSIONING.md)
- [Local acceptance](docs/LOCAL_ACCEPTANCE.md)
- [Changelog](CHANGELOG.md)

## Validation

```shell
python3 scripts/validate_public_repo.py .
python3 scripts/audit_public_tree.py .
python3 -m unittest discover -s tests -p "test_*.py"
ruff check .
```

The Hook runtime uses only the Python standard library. CI covers Ubuntu, macOS, and Windows on Python 3.10–3.13; CI does not substitute for native Hook trust or installed lifecycle evidence.

## Explicit non-goals

Context Guard is not a semantic proof system, security sandbox, transcript backup, cloud sync service, second Plan/Goal controller, agent scheduler, or replacement for tests and human review.

Version 0.8.3 adopts project instructions and plan bindings only after the user who started the root task successfully runs `context-guard adopt <project-relative-json>`. Installing a Skill, loading a template, or mentioning a plan in ordinary prose does not activate it. This release adds no `PreToolUse` Hook, does not block tools, does not modify Codex Plan state, and does not grant authority.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report sensitive issues through GitHub Private Vulnerability Reporting as described in [SECURITY.md](SECURITY.md).

Licensed under the [Apache License 2.0](LICENSE).
