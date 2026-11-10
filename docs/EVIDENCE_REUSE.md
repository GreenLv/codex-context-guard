# Historical behavior evidence reuse

The optional reuse consumer covers an executed historical-incident release
gate. It does not establish installation, native-host, performance, CI, HOL,
artifact or publication results. The original report remains the authority for
its recorded run and the normal historical release gate is unchanged.

For an owner run, provide `--execute --release-gate --report <new-path>` and
`--evidence-receipt <new-path> --evidence-environment-id <sha256>` to
`scripts/check_incident_coverage.py`. Both paths must be outside the checkout
and must not already exist. The extra environment identity is a non-secret
fingerprint from the coordinator's independently reviewed description of the
external inputs, configuration, ignored files and host state relevant to the
run. Unknown or unreviewed inputs cannot be represented as a passing review.
Keep that description, the report and the receipt private.

The owner records the complete tracked Git file inventory, index, status and current HEAD,
the Python executable and version, installed distribution versions, platform,
and the reviewed external-input identity before and after execution. Untracked
repository files, missing tracked files and symlinked tracked inputs are refused.
A changed inventory prevents reuse evidence being emitted. By default, reuse
requires the same complete inventory and HEAD, so any tracked change remains
unestablished. This does not replace the historical release gate or permit
relabeling its original result as a later-commit gate pass.

The successful owner run prints the report and receipt SHA-256 values to stderr. The coordinator
must independently review the run and retain those digests separately from the
report and receipt. A hash supplied alongside a self-authored report does not
prove the report came from an execution. The coordinator must also determine
that the external-input identity still covers ignored and external inputs;
this tool cannot infer arbitrary test dependencies or authenticate an operator.

Build the reusable record only after that review:

```shell
python tools/validation/behavior_evidence_reuse.py \
  --build-from-receipt --owner-receipt <receipt> \
  --owner-receipt-sha256 <independently-reviewed-sha256> --owner-report <report> \
  --owner-report-sha256 <independently-reviewed-sha256> \
  --environment-id <reviewed-external-input-sha256> --root . \
  --out-record <new-record>
```

Evaluate it with the same arguments, replacing `--build-from-receipt
--out-record <new-record>` with `--record <record>`. The consumer re-derives
the complete historical row and node inventory from the coverage table,
checks every result, report and receipt binding, and compares the current
complete source and environment inventory. Missing or changed inputs,
incomplete nodes, failed results and changed records are not established.
Output files are not overwritten. Exit 0 establishes this bounded behavior
coverage only; exit 1 means it was not established.

## One reviewed node across changelog edits

The following source-behavior node has a narrower, explicitly reviewed reuse
scope:

`tests/test_incident_library_regression.py::DefaultPathAuthorizationCases::test_cgi_2026_009_017_026_default_path_allows_ordinary_business`

Its fixture dispatches synthetic prompts and action strings; it does not read
`CHANGELOG.md` or `CHANGELOG.zh-CN.md`. A macOS Python file-access observation
also saw the runtime, assets and test inputs, but did not observe either log.
This observation is supporting evidence, not exhaustive dependency discovery.
For this node alone, `--node <the-node-above>` permits the bytes of those two
existing tracked changelog files and the Git commit/index/status identity to
change. Every other tracked file's name and bytes, including runtime modules,
assets, test files, caller, schema and configuration, must remain identical.
The environment and separately reviewed external-input identity still have to
match. New or removed tracked files, unknown untracked files, any other node,
and any other tracked change refuse this narrower reuse. In particular, a
changed distribution manifest is not a changelog-only change and invalidates
this node. That conservatism leaves most packaging revisions requiring reruns.

Build the full record from the original successful run first. Then add `--node`
to an evaluation, not to a build, together with
`--reviewed-node-inputs-sha256 <digest>`. Independently review the exact
registered-node source inputs and retain this digest separately from the owner
record. It is SHA-256 of UTF-8 JSON for the original receipt's `inputs_after`
`source.files` mapping after removing the two changelog keys, encoded with
sorted keys and compact separators. A digest copied from an unreviewed receipt
is not an independent review. An original run against different node code or a
changed caller requires a fresh review; a matching node name alone is insufficient.
Its `established` result covers just the
named source test, regardless of how many historical rows cite it. The original
complete owner report remains mandatory, and the historical release gate,
artifact and native checks remain separate. The owner-run and environment
review requirements above apply to this narrower route as well.
