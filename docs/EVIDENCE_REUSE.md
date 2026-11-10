# Evidence reuse contract

This page declares, for the 0.17.2 candidate and later rounds, which
behavior checks accept reuse by input identity and which must rebind to the
exact artifact or commit. It is the authoritative declaration; the
executable consumer is `tools/validation/behavior_evidence_reuse.py`, and
its tests live in `tests/test_behavior_evidence_reuse.py`.

## Reusable by complete input identity

Behavior results — behavior-suite nodes, focused regressions, and
incident-library case replays — may be reused for a new candidate only when
EVERY input that affects the result is unchanged:

- the code bytes under test (each product file bound by sha256);
- the caller/entry shape that invoked the behavior;
- the schema/fixture files the behavior reads;
- the test and judge/decoder bytes defining the node;
- the runner bytes (and its declared schema) that executed the node;
- the dependency and tool versions of the environment;
- the relevant platform state (OS family, machine, Python version).

An entry binds exactly the three file groups (`code`, `tests`, `runner`)
and the three environment keys (`python`, `platform_family`, `machine`).
Caller shape, judge/decoder logic, fixtures and dependency facts are bound
by including the files that carry them in the appropriate group — an entry
that cannot express an input that way must not be recorded as reusable.
The record's shape is validated before evaluation; a malformed or
under-bound record is REFUSED outright, never partially evaluated or
treated as reusable (a missing environment never fails open). An entry
whose every bound digest and environment field still matches is
`reusable`; anything else is `stale` with the changed input named. A
missing bound file makes the entry stale (fail closed). Reuse is per node:
a record with some stale entries is `not_established` as a whole, and
callers rerun the stale nodes rather than replaying the whole family. The
consumer exits 0 only when the whole record is established, 1 when any
node is stale, and 2 when the record is refused. Failed or
platform-specific results never transfer: they keep their original
subject, failure record and applicable conditions.

The incident-coverage consumer (`scripts/check_incident_coverage.py`)
already binds the library pin, per-record `record_sha256`, per-node test
file digests, and the candidate identity (HEAD, prepared-source digest,
dirty paths); it stays the authority for that library and follows this page.

## Bound to the exact artifact or commit — never reused

- Distribution-manifest digests, artifact identity, ZIP and marketplace
  bytes: any changed covered byte invalidates artifact-exact evidence.
- Installation, isolated install lifecycle, second-run no-op, source/cache
  parity and `smoke_installed.py` results: bound to the installed artifact.
- Native platform acceptance (Hook trust flows, background-trigger survival
  per platform, file locks and permissions, uninstall), performance gates
  (including the SessionEnd 3-second host budget), and CI/HOL runs: bound to
  the exact commit or runtime-tree digest of the observed run. A changed
  runner invalidates the native scenarios that runner executed.
- Public release evidence (tag target, release body, published notes).

`tools/validation/behavior_evidence_reuse.py` never evaluates these gates;
it reports behavior-node reuse only. The coordinator runs it against the
prior round's record when deciding which focused checks transfer; nothing
in CI consumes it automatically, and a record it cannot recognize is
refused rather than partially accepted.
