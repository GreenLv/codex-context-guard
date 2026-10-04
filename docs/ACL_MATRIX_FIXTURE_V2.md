# Protected ACL matrix fixture construction v2

This unreleased 0.15.1 validation contract constructs protected test objects while retaining the permissions supplied by their controlled inheritance source. It uses the new `explicit-retained32` profile and `incident-acl-mechanism-matrix/v2` report schema. The construction contract is `protected-explicit-retention/v2`; it does not change the product runtime or normalize user ACLs.

A protected file with four explicit allow ACEs and three inherited allow ACEs keeps all seven entries. Construction clears only the three ACE `INHERITED_ACE` bits (`I`, `0x10`), so the result has seven explicit entries. Returning four entries is still a failure. Descriptor `AUTO_INHERITED` (`AI`, `0x400`) is a separate control bit: `1004` and `1404` remain distinct targets.

## What the new profile covers

Unprotected targets (`0004`, `0404`) retain real inherited ACEs. Protected targets (`1004`, `1404`) are named `inherited_source_retained_as_explicit`, including the actor's inherited-source case. They do not cover protected targets with true `I` ACEs. Actor shape records the source of the actor entry; it does not relabel a converted entry as inherited on disk.

All protected directory cells also construct their owned target descendants as `1404`, retaining each declared inherited-source allow entry as explicit. This prevents target-only grant/deny operations from propagating into the descendants. Their original OI/CI/IO/NP flags remain unchanged. These cells are different from the old directory cells; they do not establish true inheritance or general permission equivalence for protected descendants. Unprotected directory cells retain real inheritance and strict family checks: an unexpected propagation remains a failure.

Only ordinary allow entries in the exact declared inherited tail can be converted. Count, order, SID, type, mask and all other flags must match. Inherited denies, creator substitution, object/conditional ACEs, generic rights, unknown flags, revisions or noncanonical ordering are rejected. Explicit denies retain their original order before allows; the constructor never sorts to repair an input.

## Construction and restoration

The collector exclusively creates the fixture, inventories it, verifies identities and rejects links/reparse points. Before the first ACL write it durably freezes the complete original family (`S0`). Before the new target/descendant steps it persists the complete plan calculated from controlled sources, including every final descriptor and intermediate family. Unexpected native readback cannot become the plan.

Protected descendants are assigned deepest first. Every step verifies the exact declared whole family, owned identities and read-only outside guards. A failed step persists its observation and restores the complete S0; it cannot create an accepted S1. After construction, S1 is captured from a coherent whole-family read. The existing target-only business mutation checks, exact S1/S0 restoration, `specific-write-deny/v2`, restricted-child read/write checks and zero-private-write requirement remain in force.

## Running and interpreting evidence

Select `--cell-profile explicit-retained32` with the existing `--mechanism-matrix` entrypoint in `tests/test_incident_acl_family.py`. Supply the full source commit, helper SHA-256, runner SHA-256, distinct collector and ordinary actor SID, exclusive output and fixture parent; run `--preflight` with the actual arguments first. Preflight emits all 32 mapped cells and their descriptor plans without Windows APIs, tokens or model calls. It checks inputs, not native feasibility.

A successful v2 report proves only its new construction contract. Legacy `full32` and `protected8` profiles retain v1 semantics; their earlier failures are not converted into passes. In particular, raw DACL assignment losing AI, protection returning no P bit, and protection deleting the inherited tail remain negative evidence. The v2 matrix uses no model and cannot establish a real restricted subprocess token or complete Windows host acceptance. Native v2 acceptance remains pending for this source candidate.

## One-to-one legacy mapping

Indices use the existing failure-first execution order. Every old cell remains represented; no failed cell is removed. `E` means inherited-source entries retained as explicit; `I` means true inherited ACEs. A protected directory additionally gives its target descendants control `1404` and E semantics. Files have no target descendants.

| Index | Object | Target control | Actor source shape | v2 target semantics | Target descendants |
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

[简体中文](ACL_MATRIX_FIXTURE_V2.zh-CN.md) · [Existing host acceptance contract](INCIDENT_HOST_ACCEPTANCE.md)
