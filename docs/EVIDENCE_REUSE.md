# Evidence reuse contract

This page declares, for the 0.17.2 candidate and later rounds, which
behavior checks accept reuse by input identity and which must rebind to the
exact artifact or commit. It is the authoritative declaration; the
executable consumer is `tools/validation/behavior_evidence_reuse.py`, and
its tests live in `tests/test_behavior_evidence_reuse.py`.

## Reusable by complete input identity

Behavior results — behavior-suite nodes, focused regressions, and
incident-library case replays — may be reused for a new candidate only when
EVERY input that affects the result is unchanged AND the result comes from
a real owner run:

- the code bytes under test (each product file bound by sha256);
- the caller/entry shape that invoked the behavior;
- the schema/fixture files the behavior reads;
- the test and judge/decoder bytes defining the node;
- the runner bytes (and its declared schema) that executed the node;
- the declared dependency and configuration bindings (each group present;
  an empty group explicitly means "none");
- the relevant platform state (OS family, machine, Python version).

## Records bind real owner-executed results (r1)

A reuse record (`cg-behavior-evidence/v2`) is produced ONLY by
`behavior_evidence_reuse.py --build-from-receipt` from an owner execution
receipt (`cg-behavior-execution-receipt/v1`) written by a wired consumer
during a real run — today `check_incident_coverage.py --execute
--evidence-receipt <path>`. Each entry carries the node's REAL observed
outcome and exit code, the receipt file's digest, the owner's complete
declared input mapping (code, caller, schema, tests, runner, deps,
config), and the observing environment.

- A node that did not actually pass is refused at build time (exit 2):
  failed or unknown nodes are never recorded as reusable evidence; the
  owner reruns them.
- Evaluation WITHOUT the owner receipt marks every entry
  `owner_receipt:not_verified` and the record `not_established` — a pass
  claim without a real owner run behind it is never established (exit 1).
- Presenting a receipt whose file digest differs from the record's
  binding is a refusal (exit 2), as is any malformed or under-bound
  record (missing groups, missing environment, edited receipt-node
  bindings). Tampering with the record or the receipt can only produce a
  refusal, never a reuse.
- Changed code, tests, runner, schema, config, or environment inputs make
  the affected entries `stale` with the changed input named; the owner
  reruns exactly the stale nodes through its own runner. A record with
  stale entries is `not_established` as a whole. Exit codes: 0 =
  established, 1 = stale/not verified, 2 = refused. Failed or
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
