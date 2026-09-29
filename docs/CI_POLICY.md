# CI coverage policy

Routine changes need quick feedback without repeating the entire test suite on
every interpreter. Release candidates still receive a full portability screen.
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

Main pushes select daily coverage unless the diff includes interpreter/dependency
metadata, installer or Hook launch definitions, plugin version metadata, CI
workflows/policy, compatibility/versioning documentation, or an unknown path.
Those changes automatically select full coverage. The exact path rules live in
`tools/validation/ci_policy.py`; renamed and deleted paths are included.
Changes to ordinary runtime logic, tests or reader prose normally use daily
coverage. A change to Python-version-dependent runtime behavior must additionally
receive a full run even if its filename does not trigger expansion.

Manual dispatch defaults to full. Run it on the candidate branch and verify the
run's `headSha` equals the frozen release commit:

```shell
gh workflow run ci.yml --ref <candidate-branch> -f profile=full
```

If an automatic full run already passed for that exact commit, reuse it rather
than dispatching again. A green daily run is insufficient for publication.
Changing only a tag does not rerun the matrix. Existing release evidence is not
retroactively relabeled with this policy.

For an explicitly requested routine diagnostic run, select daily:

```shell
gh workflow run ci.yml --ref <candidate-branch> -f profile=daily
```

PR validation continues to use the change map and its blocking summary. All
candidate lanes remain independent jobs. The final `Candidate CI required` job
runs even after a failure and checks every job required by the resolved profile.
A missing, failed, cancelled or skipped required job fails the summary; only
unselected lanes may be skipped. Missing classification also fails closed.
