# Distinct read-source ACL matrix fixture v3

This unreleased 0.15.1 source candidate uses the new `distinct-source32` profile, `incident-acl-mechanism-matrix/v3` report schema and `distinct-read-source-retention/v3` construction contract. It tests protected fixture construction without manufacturing repeated explicit ACEs. Native v3 acceptance is not run; source models cannot establish Windows behavior or a real restricted subprocess token.

A protected file target keeps four explicit management entries and three different inherited-source read entries. Clearing only I preserves all seven entries without making the last three copies of the first three. The source principals are existing well-known Everyone (`S-1-1-0`), Authenticated Users (`S-1-5-11`) and Builtin Users (`S-1-5-32-545`). Their specific mask `0x1200a9` permits read/list/traverse, not writes; their source flags are OI|CI. This is meaningful fixture coverage, not permission equivalence to the old full-control source.

## Scope and failed subjects

The collector, System, Administrators and OWNER_RIGHTS explicit management entries remain. The owned root keeps that management base without inheritance flags and adds the three inheritable read sources. Actor source shape remains missing, explicit allow, inherited-source allow or explicit deny. Missing means no direct actor entry; it does not assert the absence of effective group read access. Actor and collector must differ from each other and every fixed role before any fixture is created or ACL is written. Unknown principals, masks, ACE types, flags, controls and noncanonical or duplicate constructed entries fail closed.

Every one of the old 32 cell identities remains mapped below. The new sources apply to all cells. File targets and the leaf of every protected directory are checked together; repairing only the first file would leave eight directory leaves with the old repeated-entry problem. v1 and v2 reports keep their own identities and failures. A setter returning success while changing seven planned entries to four remains failed; v3 success must not reclassify that observation or prove universal Windows deduplication.

Unprotected cells keep true I ACEs. Protected targets are `inherited_source_retained_as_explicit`: only I is cleared, retaining SID, type, mask, order and the other flags. Descriptor AI is separate from ACE I; controls `1004` and `1404` remain distinct. All protected directory cells declare owned target descendants as `1404`, also retaining their controlled inherited-source allow entries as explicit, deepest first before S1. These cells do not establish protected true-I coverage or equality to the v1/v2 permissions.

## Construction and the setter witness

The fixture is newly and exclusively collector owned. Original family S0 is durably saved before the first write. All constructed target/descendant descriptors, propagation states and processing order are precomputed from the declared sources, persisted before those new steps and verified after each operation. Links/reparse points, changed identities, changed inventory or outside guards remain failures. The original S0, S1 and observed ACLs are never deduplicated or normalized.

For Named construction writes, a bounded fixture-only wrapper observes the existing `GetSecurityDescriptorDacl` call. It verifies that the returned PACL points into the exact live planned descriptor buffer. It captures the complete ACL from that owned buffer without dereferencing an unbound pointer, saves raw ACL bytes alongside the original private snapshots (requesting mode0600 where supported) and persists ordered ACE hashes, size/count, selected API and flags before calling the original setter once. Extraction does not add an API call. Pointer, buffer, path, flags, call-count or evidence-storage mismatch stops construction without a fallback or retry. The wrapper forwards native results and preserves a primary failure if later evidence persistence also fails.

The witness covers Named fixture construction, including the `1404` intermediate used to construct `1004`. It does not cover raw `SetFileSecurityW` assignment, business grant/deny or restoration. Those retain their existing strict checks. Raw ACL files stay in the prevalidated private output directory; POSIX file mode alone does not establish a Windows ACL boundary. Transport may contain only hashes, structures and a bound artifact index. Product Hook runtime and the original ACL helper are unchanged. SDK mocks prove Python forwarding and rejection behavior, not actual Windows ABI or internal normalization.

After construction, coherent whole-family observation freezes S1. Target-only business mutations must leave other family objects and outside guards unchanged; exact complete S1 and S0 restoration remain mandatory. `specific-write-deny/v2`, original/granted/denied baselines, actual restricted-child read and denied writes, zero private writes, normal Hook trust and the original host gates are unchanged. The matrix cannot replace those observations.

## Invocation and acceptance

Use `python -B -m tests.test_incident_acl_family --mechanism-matrix --cell-profile distinct-source32` with full source commit, helper/runner SHA-256, distinct actual actor/collector SIDs, exclusive output and fixture-parent arguments. First run `--preflight` using the actual arguments. Output storage must neither overlap source nor be its ancestor. Preflight checks all 32 mapped descriptors without APIs, tokens or models; it cannot certify native feasibility.

Actual execution stops on the first failure after saving evidence and attempting complete restoration. Remaining cells are explicitly not run. The full original Windows host profile must remain not run until a coordinator-approved prerequisite is satisfied; a green matrix alone cannot certify it. Native budgets and authority are external to this CLI: no new native run is authorized by this source candidate.

## Mapping from v1 and v2

Order remains failure first. Each row keeps the same object, target control and actor source shape as v1/v2. All v3 rows use the three distinct read-source principals and retain the explicit management base. E means inherited-source retained as explicit; I means true inheritance. Files have no target descendants.

| Index | Object | Target control | Actor source shape | v3 target semantics | Target descendants |
| --- | --- | --- | --- | --- | --- |
| 1 | file | 1404 | missing | E | — |
| 2 | file | 0004 | missing | I | — |
| 3 | file | 0004 | explicit | I | — |
| 4 | file | 0004 | inherited | I | — |
| 5 | file | 0004 | deny | I | — |
| 6 | file | 0404 | missing | I | — |
| 7 | file | 0404 | explicit | I | — |
| 8 | file | 0404 | inherited | I | — |
| 9 | file | 0404 | deny | I | — |
| 10 | file | 1004 | missing | E | — |
| 11 | file | 1004 | explicit | E | — |
| 12 | file | 1004 | inherited | E | — |
| 13 | file | 1004 | deny | E | — |
| 14 | file | 1404 | explicit | E | — |
| 15 | file | 1404 | inherited | E | — |
| 16 | file | 1404 | deny | E | — |
| 17 | directory | 0004 | missing | I | I |
| 18 | directory | 0004 | explicit | I | I |
| 19 | directory | 0004 | inherited | I | I |
| 20 | directory | 0004 | deny | I | I |
| 21 | directory | 0404 | missing | I | I |
| 22 | directory | 0404 | explicit | I | I |
| 23 | directory | 0404 | inherited | I | I |
| 24 | directory | 0404 | deny | I | I |
| 25 | directory | 1004 | missing | E | 1404 / E |
| 26 | directory | 1004 | explicit | E | 1404 / E |
| 27 | directory | 1004 | inherited | E | 1404 / E |
| 28 | directory | 1004 | deny | E | 1404 / E |
| 29 | directory | 1404 | missing | E | 1404 / E |
| 30 | directory | 1404 | explicit | E | 1404 / E |
| 31 | directory | 1404 | inherited | E | 1404 / E |
| 32 | directory | 1404 | deny | E | 1404 / E |

[Previous v2 contract](ACL_MATRIX_FIXTURE_V2.md) · [简体中文](ACL_MATRIX_FIXTURE_V3.zh-CN.md)
