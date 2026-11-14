# CI coverage policy

A manual full-profile run builds a manifest-exact candidate ZIP only after
the required candidate jobs pass. The artifact includes a source-commit,
runtime-digest, checksum, size and inventory receipt; repeat-pack equality is
checked before upload. Its name binds the workflow commit. Native executors
download and acknowledge these same bytes rather than rebuilding the release
on each platform. This Actions artifact is escrow, not a tag or GitHub Release;
routine pushes and tag creation do not produce another canonical ZIP.

Routine changes need quick feedback without repeating the entire test suite on
every interpreter. Release candidates receive a risk-selected portability screen.
The runtime minimum remains Python 3.10; this policy changes where tests run,
not which interpreters users must install.

## Daily and full profiles

| Profile | Full behavior suite, phase-3 audit and source self-test | Additional checks |
| --- | --- | --- |
| Daily | Ubuntu 3.10 and 3.14; macOS 3.12; Windows 3.12 | Windows 3.10 and 3.14 platform suite and source self-test |
| Full | Ubuntu, macOS and Windows, each on 3.10, 3.11, 3.12, 3.13 and 3.14 | Windows portable installed-runtime acceptance on 3.12 |

Daily coverage has four full lanes and two focused lanes, compared with the old
twelve full lanes. Full coverage has fifteen full lanes and omits the redundant
focused lanes. Python 3.14 is the newest stable minor selected for this policy;
versions are explicit and reviewed when the supported range changes.

Identity, repository, privacy, lint and compile checks run once in either
profile. Windows portable installed-runtime acceptance also runs in daily mode
when the existing change map invalidates native artifact or runtime evidence.
It uses Codex CLI 0.158.0 and checks preflight before execution. This CI job does
not establish real-host trust, model behavior or native desktop acceptance.

The focused suite selects six existing modules in
`tools/validation/run_windows_platform_suite.py`: action grounding, historical
incident regressions, terminal wire handling, Stop process regressions,
acceptance identity and plugin management. These cover physical paths and
quoting, terminal text, subprocess invocation, unusual filenames, cache
integrity and installer no-op behavior. They include the Windows path cases
found during 0.14.3 validation. They do not replace full product regression or
live-host acceptance. Missing modules, empty/all-skipped modules and test errors
fail the runner; capability-specific skips remain visible.

## Selection and release procedure

Main pushes select daily coverage for ordinary changes and full coverage for
compatibility, dependencies, launchers, CI policy, shared identity or unknown
inputs. The selector verifies version-only changes to supported metadata by
comparing the actual before and after contents. A changed dependency or Python
constraint remains full. Reader-document changes use daily plus separately
selected artifact checks; packaging implementation changes require full.
Renames and deletions include both sides, and unreadable metadata fails closed to
full. A manually requested daily
profile cannot downgrade the inferred minimum.

A candidate must pass the selected profile and required summary on its exact
commit. A manual daily dispatch requires `base_sha` as the complete actual
baseline commit, a strict ancestor of the candidate; missing, equal or invalid
baselines fail classification. The baseline must cover the whole release diff,
not merely the last commit. If the earlier full run already passed on the exact
commit, reuse it; tag creation does not require another run. Manual full remains
available for compatibility campaigns. CI evidence does not establish live
host behavior, trust or installation.

## Exact-commit run reuse

The `ci_reuse` job is that rule's real result consumer, and it runs only in
the full profile. It queries the official Actions API for completed runs of
this workflow on the exact head commit, re-derives the prior run's
full-coverage facts from its job list, and emits the
`cg-ci-reuse-evidence/v1` receipt (uploaded as
`ci-reuse-evidence-<sha>-<attempt>`) that records the consumed run, its job
conclusions and every check that ran.

Reuse is confirmed only when a prior run on this exact commit, under this
same workflow, completed successfully with every full-profile job passed:
classification, the static gate, all fifteen lanes, the Windows portable
acceptance and the `Candidate CI required` summary. Skipped or missing lanes
mean the run is not a genuine full run — most often a run that itself reused
an even earlier one — and such candidates are skipped, never cited, so reuse
never chains. When the prior run's manifest-exact candidate artifact exists,
its receipt is downloaded and must bind this exact source commit and the
runtime digest of this checkout; the artifact is additional escrow, so its
absence does not block reuse, but any mismatch refuses the verdict.

A confirmed reuse skips the fifteen lanes and the portable acceptance of the
current run and reduces the required summary to `classify`, `static` and
`ci_reuse` — all three still demanded, and any failed or cancelled job
anywhere in the run still fails the summary. Everything else answers denied:
missing evidence, a failed lane on the exact commit, identity drift or any
API or local failure falls back to running the ordinary lanes, which is the
safer direction. Reuse consumes job and artifact evidence only; it does not
establish live host behavior, trust or installation.

Formal performance comparison is required when performance-sensitive behavior
changes or a task explicitly requires it; it is not a universal per-release
campaign. Full legacy formal results retain their original semantics. A scoped
formal run uses `perf_ab.py --formal --scope-manifest MANIFEST --attempts N`,
where the manifest declares `perf-scoped/v1`, selected cells, N (at least 20),
exact baseline/candidate runtime digests, and explicit relative and absolute
budgets for each affected metric. The JSON keys are `schema`, `cells`,
`attempts`, `baseline_runtime_digest`, `candidate_runtime_digest`, and
`budgets`. Each metric budget has finite nonnegative `relative` and `absolute`
numbers; `elapsed` is in seconds and `peak_bytes` is in bytes. The budget set
must include `elapsed`, plus `peak_bytes` when `memory_stop` is selected.
Pass that same manifest to
`perf_ab_verdicts.py --scope-manifest MANIFEST RAW`; a partial, failed,
censored, identity-drifted or budget-drifted batch is rejected. Both practical
limits and the statistical lower bounds must be exceeded to report a material
regression. A pass requires the upper bound to exclude exceeding at
least one limit; intervals crossing the decision boundary are inconclusive and
return nonzero. No default tolerance is invented and the tool never automatically
retries or adds samples. Old failures remain unchanged.

PR validation continues to use the change map and its blocking summary. All
candidate lanes remain independent jobs. The final `Candidate CI required` job
runs even after a failure and checks every job required by the resolved profile.
A missing, failed, cancelled or skipped required job fails the summary; only
unselected lanes may be skipped. Missing classification also fails closed.
