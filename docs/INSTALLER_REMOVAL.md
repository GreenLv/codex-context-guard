# Marketplace-only source candidate (Unreleased)

This candidate removes the project installer from tracked source and runtime
artifacts. No installer implementation is renamed or moved. Codex owns plugin
installation. The distinct `codex-context-guard-v016` marketplace identity is
experimental; the released marketplace and consumed 0.15.1 objects are not
modified by this source change.

## Retired implementation and tests

- `scripts/manage_plugin.py`: removed entirely, including staging, registration,
  transaction rollback, archive repair and automatic interpreter binding.
- `tools/validation/candidate_namespace.py`: removed; it invoked the old cache,
  archive and installation transaction. The historical commentary live-runner
  preflight now refuses execution until an official-marketplace profile is reviewed.
- `tests/test_manage_plugin.py`: retired tests only the removed installer.
- `tests/test_cg0160_installer_transaction.py`: retired tests only the removed transaction.
- `tests/test_candidate_namespace.py`: retired tests only the removed namespace installer.
- Installer-execution methods in `test_native_acceptance_strict_noop.py` are
  retired; independent snapshot safety regressions remain. Their deletion does
  not waive the required official-marketplace install/no-op/preservation gates.

## Replacement and evidence boundary

`artifact_identity.py` independently computes read-only runtime and distribution
hashes. It has no installation, registration, HOME, staging or cache write API.
The native entrypoint's default `portable_runtime` path now uses official Codex
commands only in an internally created fresh HOME, with separate host temp and
OS/profile/XDG directories. It installs a manifest-exact release ZIP, binds the
official add response and exactly one enabled installed list record to the
retained release source, checks every ZIP file in the cache and runs smoke.
Its second documented procedure reads status and exact identity/parity, and
stops without registration or add. The original anchored HOME-13 snapshot
compares final paths, modes and bytes, not absence of intermediate writes;
a disclosed synthetic 0.15.1 cache additionally keeps nonzero object identities.
Direct repeated add is not claimed idempotent. This has no operator HOME option.

The optional `--release-zip` preserves and validates a prebuilt ZIP so native
platforms can consume identical artifact bytes; without it, the one local build
is separately hashed. Matching source alone does not prove equal ZIP bytes.
The result records ZIP SHA-256, size and entry count. A clean exact source commit
is still required; uncommitted development observations cannot become v2 passes.
`--installed-plugin-root` remains a separate artifact-only inspection that
returns pending and cannot satisfy installation, no-op, trust or task continuity.
Long-term refresh, GUI discovery, normal trust, real old-cache preservation and
old task continuity remain separate native gates.

Existing `interpreter.conf` readers and runtime validation remain. No code in
this candidate creates the binding. GUI hosts must discover supported Python
or already have a valid binding; no GUI PATH repair is claimed.

The removed installer no longer provides archive restore, transaction rollback,
or consumed-cache preservation around Codex operations. Merely choosing a new
marketplace identity does not prove host independence, continued old task Hooks,
or enable/disable behavior. Preserve old objects and daily configuration until
those exact native gates have been observed. No old HOME is migrated.

Cold reader review and final native installation acceptance are pending.
The release ZIP includes the enumerated Markdown documentation so its README
links remain usable; no Git metadata, tests or acceptance data are packaged.

## Retired test-family obligations

| Removed module | Retired implementation families | Still required |
| --- | --- | --- |
| test_manage_plugin | custom archive indexing/repair, staging migration, lock/bootstrap, Codex subprocess HOME routing and binding publication | Official-marketplace old-object protection and no-op remain pending; release ZIP excludes Git metadata and unreviewed private inputs; launcher binding reads retain runtime tests |
| test_cg0160_installer_transaction | custom registration/staging rollback, trusted archive repair and transaction cleanup | Independent manifest tests retain missing/corrupt/linked/drift refusal and exact tracked release set; official failure preservation is pending |
| test_candidate_namespace | private operator scope record, authenticated-home idle scan, namespace lock/config rollback | Removed tool cannot touch any HOME; official install preservation, unrelated-config isolation and exact returned identity remain pending |

Installer method tests removed from the snapshot module: exercise helper,
second-apply/no-op, rewrite semantics, mutation matrix, portable detached-holder,
manager binding/dry-run, and the combined execution/redaction case. Independent
file-type, ancestor, replacement and redacted snapshot-error controls remain.

The product historical-case locator now points to synthetic official identity/source
positive and negative controls as an analogue only. Canonical historical verdicts
are unchanged; earlier installed/native executions are not rebound to this candidate.
The strict second-operation no-op requirement is not satisfied by an ordinary
repeat `codex plugin add`; do not infer idempotence from a successful exit.
