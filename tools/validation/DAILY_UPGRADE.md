# Daily upgrade entry

`tools/validation/daily_upgrade.py` is the maintained operator entry for
routine upgrades of the daily HOME's `context-guard@codex-context-guard`
installation. It replaces the per-round, hand-assembled upgrade scripts: one
plan file drives prepare, resumable apply and repeatable verification, and
every result is bound to the exact plan, CLI, interpreter and artifact
identity that produced it.

It is deliberately different from `native_upgrade_acceptance.py`, which
serves isolated release acceptance and refuses the daily HOME. This entry
never impersonates that acceptance, never edits a consumed cache, never
deletes or disables a Hook, never copies credentials, and never creates a
login. Every host change goes through official Codex marketplace commands,
and Hook trust stays with the normal official review interface.

## Boundaries

- Stable identity only: the plan must name the stable entry
  `context-guard@codex-context-guard` in the stable marketplace. No
  per-version entries are created.
- No publication, no release artifact building, no cache repair. The tool
  consumes a release ZIP you have already verified and extracted, or a
  product checkout, as the marketplace source.
- No model calls, no trust bypass, no `--help` probing of unknown CLIs.
  Command readiness probes use `--version`-style oracles, parse-only
  launcher checks, the launcher's real `print-argv` echo mode and read-only
  process enumeration only.

## Plan file

Write a JSON plan outside the repository, for example as private local
state (never commit it):

```json
{
  "schema": "cg-daily-upgrade-plan/v1",
  "entry": "context-guard@codex-context-guard",
  "marketplace": "codex-context-guard",
  "target_version": "0.17.4",
  "artifact_dir": "/absolute/path/to/extracted-release",
  "cwd": "/absolute/path/to/an/existing/directory",
  "desktop_executable": "/absolute/path/to/the/Codex/Desktop/binary",
  "sandbox_markers": [],
  "cli": "/absolute/path/to/codex",
  "data_dir": "/absolute/path/to/plugin-data"
}
```

- `artifact_dir` must be a complete release root whose reviewed distribution
  manifest matches its bytes and whose `plugin.json` version equals
  `target_version`.
- `desktop_executable` is the exact Desktop host binary path. Host
  identification matches this exact executable identity plus parent-child
  links — never a process name and never a `--host-stopped` declaration.
- `sandbox_markers` are exact executable paths of sandbox helpers. They are
  recorded and never treated as the Desktop host; they do not gate the swap.
  Leave this list empty when no helper identity has been verified.
- `cli`, `expected_cli_version` and `data_dir` are optional. `data_dir` is
  only observed (retention `--policy show`); the existing automatic cleanup
  defaults are not changed by this tool. If supplied, `expected_cli_version`
  must equal the exact output of the selected CLI's `--version`; do not copy
  a version from another machine.

## Phases

All commands run the launcher (macOS/POSIX sh, Windows PowerShell), which
selects a Python 3.10+ interpreter and starts exactly one Python process
with `-B`:

```shell
tools/validation/run_daily_upgrade.sh daily --plan PLAN --output OUTPUT ACTION
tools/validation/run_daily_upgrade.ps1 -Target daily -Arguments @("--plan", "PLAN", "--output", "OUTPUT", ACTION)
```

Choose an existing owner-private results parent outside the repository,
daily HOME and target artifact. `OUTPUT` names a new child directory there;
prepare creates that child exclusively. Existing receipts are never
replaced. Apply resumes in the prepared batch, and each verify writes a new
numbered receipt. For example, after writing the private plan:

```shell
plan="/absolute/path/to/plan.json"
batch="/absolute/path/to/private-results/batch-0173"
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --preflight-commands
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --prepare
# Finish or hand off dependent tasks and quit Desktop before replacing its installation.
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --apply
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --verify
```

```powershell
$plan = 'C:\Path\plan.json'
$batch = 'C:\Path\PrivateResults\batch-0173'
$entry = '.\tools\validation\run_daily_upgrade.ps1'
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--preflight-commands')
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--prepare')
# Finish or hand off dependent tasks and quit Desktop before replacing its installation.
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--apply')
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--verify')
```

When prepare reports `already_current`, omit apply and run verify directly.
Normal Hook review may be needed between apply and a successful verify.

1. `--preflight` — read-only readiness: pinned executable identities with
   digests, the current official installation state via marketplace and
   scoped plugin readbacks, artifact manifest verification, an optional
   retention-policy observation and a host process inventory. This standalone
   action creates its own output directory; use a separate directory from the
   later prepare/apply/verify batch.
2. `--preflight-commands` — the same, plus side-effect-free probes of the
   exact command families a run can issue. Never reaches a trust step and
   never probes with `--help`.
3. `--prepare` — binds the subject and decides the swap requirement. If an
   installation exists and the Desktop host is running (or its state is
   unknown), the result explains exactly why the swap needs the host
   stopped. When the installed version already equals the target, prepare
   reports `already_current` and nothing is swapped.
4. `--apply` — the swap. Requires the host observed absent (by exact
   executable identity, with zero unreadable Desktop candidates) whenever an
   existing installation is being replaced. Stages run through official
   commands — marketplace remove, marketplace add of the verified artifact,
   plugin add, closing readbacks — and each destructive stage writes a
   durable intent event to `apply-events.jsonl` before it runs and a fact
   event afterwards. If a run is interrupted, re-run the same apply command:
   every stage is reconciled against official readbacks first, so completed
   work is never repeated, a marketplace that already moved is skipped, and
   a registration that changed outside the batch is refused. An official
   add whose summary is unreadable is recorded (`summary_parse_failed`) and
   judged by the scoped list readback, not retried.
5. `--verify` — fresh official readbacks, exact artifact parity between the
   plan artifact and the installed cache, and a read-only fresh-client Hook
   probe (initialize + `hooks/list` over the official app-server transport,
   no model turn) that records which Hook sources a brand-new client
   actually loads. The verdict requires the exact nine events, one row each,
   plugin source, no inventory errors or warnings, trusted and enabled rows
   and an enabled official readback. Statuses: `passed`,
   `hook_trust_pending` (review the nine Hooks through CLI `/hooks`, or
   Desktop's Review hooks / Settings > Hooks),
   `hook_inventory_incomplete` (missing, duplicate, unknown-event,
   wrong-source or flagged rows — never a pass), `restart_required` (a fresh
   client still loads the old source), `loaded_none` (no Context Guard Hook
   sources observed), `loaded_unknown` (probe failed; never reported as a
   pass). Every verify re-measures the live machine — a prior
   receipt, passed or not, is a historical result and never substitutes for
   current state; each run records its verdict in the next exclusive
   numbered receipt (`verify.json`, `verify-2.json`, …) and prior receipts
   are never replaced. Re-running the same verify command after an operator
   step is therefore the intended resume; destructive apply stages are the
   only resume-once work.

Exit codes: `0` completed; `1` pending, including an observation gap or
non-passing verify; `2` refused inputs or an execution error. Inspect the
reason and saved journal/readbacks before deciding what to do. Correct
refused inputs or unavailable prerequisites first. Resume an interrupted
apply with the same command only when its bound inputs still match; a
nonzero exit does not mean that no stage changed. After completed apply or
`already_current`, continue with verify rather than reinstalling. A failed
or pending verify can be repeated after its cause is resolved; an explicitly
selected `--verify-output` needs a new filename on the next attempt.

## Thin continuation and controlled rebinding

Two dispatcher actions remove the remaining hand-assembly between stages.
Neither adds its own identity rule: every stage still re-derives its subject
and refuses drift exactly like the directly typed command.

- `--resume` — one same-command continuation over the batch's receipts. With
  no prepare receipt it prepares; an unapplied prepared batch is applied
  (the host-absent gate still answers with its one precise instruction when
  the Desktop host is running); and every arrival verifies. Re-running the
  same `--resume` command after each operator step therefore completes the
  whole batch — prepare, apply, verify — without re-typing per-stage
  commands or re-deriving arguments. Exit `1` means one precise operator
  step is pending (quit the host, review the Hooks); exit `2` means a
  refusal that the typed commands would have produced identically.
- `--resume --wait [--wait-minutes N]` — the same continuation with a
  bounded in-process wait: when apply answers that the Desktop host must be
  observed absent, the process polls the read-only pinned-executable
  inventory until the host has actually exited (default ceiling 60 minutes,
  maximum 720, poll every 15 seconds) and then retries apply itself, whose
  fresh apply-time inventory remains the deciding gate. Nothing is ever
  closed or signalled and unrelated processes never gate the wait; Hook
  trust still goes through the official review interface afterwards. The
  batch receipts are the persistence layer — killing the wait loses
  nothing, and the same command resumes.
- `--rebind` — controlled host re-identification for an unstarted
  batch. When the only change after preparation is the pinned desktop
  executable's bytes (the host auto-updated in place at the same path),
  rebind re-derives the full preflight subject, records the judgment in an
  exclusive `rebind.json` audit receipt, keeps every prior receipt
  untouched, and writes the next numbered prepare receipt (`prepare-2.json`,
  …) bound to the new host identity. Continue with the same `--resume`
  command — it picks the newest prepare receipt automatically, and the
  apply receipt records which prepare receipt it consumed.

  A numbered prepare receipt is adoptable only when its rebind audit binds
  both the receipt name and the subject digest; the audit is written after
  its receipt, so an interrupted rebind leaves an orphan that resume, apply
  and verify refuse to adopt, and re-running `--rebind` writes the next
  exclusive pair from the last audited receipt. An audit whose target
  receipt has been removed refuses everywhere.

  Rebinding also re-audits provenance: both the prepared host and the
  changed host bytes must carry a verified platform publisher signature.
  On macOS the identity must pass an explicit trust-anchor requirement
  (`codesign --verify --strict --test-requirement '=anchor apple generic
  and anchor trusted and certificate leaf[subject.OU] = "TEAM"'`, with the
  team identifier strictly format-validated) — `--verify` alone or a
  self-reported `TeamIdentifier` string is not accepted, and the rebind
  evaluates the requirement against the prepared publisher identity. On
  Windows the boundary is a Valid Authenticode status with the same
  certificate thumbprint; certificate rotation changes the thumbprint and
  is refused, never auto-allowed. Any unverifiable signature refuses.

  Any other input change (CLI, artifact, plan, helper closure, interpreter,
  sandbox markers) refuses with its own category, because those require a
  re-reviewed plan and a fresh batch. A batch whose apply already began is
  never rebound: recover it by its original journal.

```shell
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --resume
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --rebind
```

```powershell
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--resume')
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--rebind')
```

A tool update between preparation and continuation (this file's own commit
changing `daily_upgrade.py`) is helper-closure drift: both `--resume` and
`--rebind` refuse it, and the fallback is a new batch directory with a fresh
read-only prepare reusing still-valid test and acceptance evidence.

## What stays manual

Only what the platform actually requires of a human:

- Quitting the Codex Desktop host before a swap that replaces a consumed
  cache — the observed local-source CLI route removes the previous version's
  cache. This tool has not established a safe live replacement. Apply refuses
  until the host is observed absent, then one command completes the batch.
- Hook trust after the swap, through CLI `/hooks` or Desktop's Review hooks /
  Settings > Hooks.
- Credential copies stay governed by existing permissions; the tool never
  outputs or transfers credentials and never creates a login in isolation.

## Official same-entry refresh semantics (macOS fixtures, 2026-11-14–15)

A controlled isolated-HOME fixture ran the real installed CLI (0.169.0) and
recorded what each official route does to the version cache slot and the
fresh-client Hook inventory (`cg-daily-loaded-probe/v1` receipts, private):

- `codex plugin marketplace upgrade <name>` exists but refuses non-Git
  marketplaces ("not configured as a Git marketplace"). The verified local
  artifact route this tool drives therefore has no official `upgrade`
  subcommand; refresh for a local source is add/remove based only.
- A bare official re-add of the same version replaces its slot directory
  (new inode, fresh install). A separate 0.17.3 → 0.17.4 control kept the
  registered local source directory and used no remove command: the old
  107-file cache was intact immediately before `plugin add` and absent
  immediately afterwards, before any following list call. The new slot had
  110 files. This CLI/local-source route therefore cannot preserve code
  needed by an active old task. The control used reviewed distribution files,
  not the final CI ZIP, and is not final-artifact acceptance.
- `plugin marketplace remove` retires the registration; the slot directory
  remained on disk in the fixture, and the following re-add created a fresh
  slot — consistent with the resumable apply's readback-driven staging.
- The original isolated home never granted Hook trust. Its fresh-client
  inventories showed nine enabled but untrusted Hooks before and after each
  operation; that does not test migration of an existing trust decision.
  Hook review remains in the official interface.
- The macOS Desktop host observed in daily use lives inside
  `ChatGPT.app`'s versioned `Codex Framework.framework` tree, so a host
  auto-update can change the pinned executable's **path**, not only its
  bytes. `--rebind` deliberately refuses a path change (the plan pin moved);
  the operator writes a new plan and starts a new batch, reusing still-valid
  test and acceptance evidence.

These observations do not establish running-Desktop loading or old-task
continuity. The [official local-plugin guide](https://developers.openai.com/plugins/build/plugins)
also instructs users to restart the desktop app after changing a local plugin.
The tool therefore keeps its host-absent apply gate and makes no no-restart
promise. The source-checkout tools and CI changes can be adopted without
replacing the daily plugin; existing 0.17.3 Hook behavior is unchanged.

## Records and limitations

The standalone preflight directory keeps `preflight.json`. An upgrade batch
keeps `prepare.json`, any controlled rebind records (`rebind.json`,
`rebind-2.json`, …, and their numbered `prepare-2.json`, … receipts), any
apply journal/receipt (`apply-events.jsonl`,
`apply.json`) and the numbered verify receipts
(`verify.json`, `verify-2.json`, …), plus the probe journal
`probe/loaded-N/rpc.jsonl`. Every subject binds the digests of the tool, its
executed helper closure (`scripts/`, `tools/validation/`,
`tools/guard_state_migration.py`), the platform launchers and the pinned
process-enumeration executables, so any helper drift between phases is
refused. Results contain host-local paths and process
facts and are private to the operator; never commit them. The fresh-client
probe observes only what a new client would load — it cannot prove what the
already-running Desktop has in memory, which is precisely why the swap
requires the host stopped. Sandbox services observed at swap time are
recorded in the apply result. Process identification on macOS uses `ps` plus
libproc executable paths and treats other-user unreadable processes as
kernel-family; on Windows it walks one complete Toolhelp snapshot (`PROCESSENTRY32W`,
no elevation, all sessions): a snapshot image basename that differs from
every pinned candidate basename — after the truncation and shape guards —
is negative evidence only for those exact pinned images; same-name rows
get a second-snapshot PID-reuse confirmation and then a bounded
`QueryFullProcessImageName` full-path read, and unreadable, truncated,
shape-anomalous or incomplete-walk observations keep Desktop candidacy
when they have not excluded the Desktop image, forcing status `unknown`.
An unreadable sandbox
candidate with a different image basename is recorded as unverified and
does not become a Desktop candidate; a matching basename remains unknown.
WMI names never participate.
