# Context Guard 0.9 development plan

Status: **In progress**

Target: plugin `0.9.4`, Stop protocol `2.0.0`

Latest published release: `0.8.12`

This is the authoritative continuation plan for the 0.9 line. It is updated at
phase boundaries, not as a command transcript. The protocol rationale is in
[Protocol-authoritative completion](PROTOCOL_AUTHORITATIVE_COMPLETION.md).

## Goals and non-goals

The goal is to make a complete, authenticated, turn-bound checkpoint the only
transition to whole-task completion. Natural-language classification remains a
diagnostic signal and cannot alter the final Stop outcome, pending state, or
continuation count. The release also establishes a maintainer-local,
append-only incident corpus and a reviewed public regression set.

This release does not broaden Context Guard into a security sandbox, an
arbitrary semantic verifier, or a visual-understanding system. It does not
change schema 7, classifier 2.3.2, Proof protocol 1.0.0, Execution protocol
1.0.0, or the eight-Hook wire. It does not mutate consumed 0.8.12, 0.9.0,
  0.9.1, 0.9.2, or 0.9.3 caches.

## Protocol decisions

Stop protocol 2.0.0 evaluates, in order: state and prompt integrity; private
metadata; staged-control validity; complete checkpoint; explicit user
persistence; typed disposition; safe default yield. Only a complete checkpoint
may write completion state. Missing control, `user_wait`, `external_wait`, and
valid `deferred` controls yield while preserving pending work. Invalid,
partial, stale, replayed, or conflicting controls and privacy or state-integrity
failures remain fail closed.

`claims_whole_completion` is excluded from the authoritative path. Its result
is retained in `observed_outcome`. New authoritative decisions use
`protocol_default` or `protocol_user_persistence`; `nlp_hard_gate` remains
schema-readable only for historical decision logs. Loading Stop 1.1 state
preserves requirements, evidence, proof, and decision history while discarding
an unauthenticated in-flight legacy control.

## Phase status

| Phase | State | Exit condition |
| --- | --- | --- |
| Contract and history audit | Completed | 0.8.12 behavior, incident families, and immutable-cache boundary identified |
| Incident infrastructure | In progress (POSIX passed; Windows 0.9.4 focused ACL gate passed) | private corpus validates; reviewed public fixtures, manifest benchmark, and native permission boundary pass |
| Stop 2.0 implementation | Completed | classifier has no authoritative influence; migration and decision sources pass |
| Regression and documentation | Completed | 10,000 seeded transitions plus subsystem regressions and bilingual adopter docs pass |
| Source acceptance | In progress (Windows 0.9.4 gate running; macOS pending) | validator, privacy audit, tests, self-test, Ruff, compile, and diff gates pass |
| Installed and native acceptance | In progress (macOS 0.9.2 passed; Windows 0.9.4 pending) | isolated install/no-op/parity/smoke/recovery plus independent fresh-Hook evidence pass |
| Publication | Pending | PR/main CI, HOL, tag CI, bilingual Release, and public readback pass in order |

## Exit conditions

- No completion transition occurs without a complete authenticated checkpoint.
- Identical structured control produces identical authority state for every
  tested completion wording; known false-continuation fixtures produce zero
  retries.
- Every invalid control is rejected, and historical privacy and integrity
  fixtures remain contained.
- A fixed seed covers at least 10,000 state transitions and multilingual,
  quotation, code, hypothetical, negated, first-person, and attributed speech.
- Receipt, Plan mirror, visual readback, scope, compaction, schema migration,
  cache lifecycle, and installed behavior regressions pass.
- Source, install, native macOS, native Windows, CI, HOL, tag, and Release
  evidence are recorded as separate gates; none substitutes for another.

## Verified evidence boundary

The last verified implementation commit is `37612bf`; documentation successor
`d8fbc97` records the current public evidence boundary and passes the affected
contract, repository, privacy, identity, and diff gates. The 0.9.2 source tree
passes repository validation, the tracked-tree privacy audit, 226 tests with
five capability-aware skips, the eight-Hook self-test, Ruff, external-cache
compilation, and `git diff --check` on macOS. Its reviewed fixture
manifest is `ec6dc9fdc4b63b8f4e18b4f4ca2335d86665e6e39be4444e829262811569af54`;
0.8.12 reproduces two target false continuations and the 0.9 line produces
zero. The consumed 0.9.1 implementation commit `02e7f57` also passes isolated
install, strict second no-op,
source/staging/live/archive parity, installed self-test and lifecycle smoke,
Stop 1.1 recovery migration, and a native macOS fresh-Hook replay on Codex CLI
0.150.1. The real replay recorded `observed_outcome=gate_completion_claim` but
the authoritative `protocol_default/allow_neutral` outcome, zero continuations,
preserved pending state, and a completed `SessionEnd`. The default-home upgrade
restored archived 0.8.12 and consumed 0.9.0 live trees without changing their
trusted archive parity.

Native Windows at predecessor head `111cb7f` passed the eight-fixture benchmark,
repository validation, and privacy audit, then stopped at two source failures
that treated POSIX `0600`/`0700` bits as Windows privacy evidence. Candidate
`02e7f57` replaced that contract with `Set-Acl`, but the native Windows rerun at
documentation head `360fad2` stopped when a standard user token lacked
`SeSecurityPrivilege`. No fallback, skip, install, or cache mutation occurred.
Implementation `37612bf` advances to 0.9.2 and replaces `Set-Acl` with a native
DACL-only call that passes null owner, group, and SACL pointers, then performs
an independent access-rule readback. The exact 0.9.2 tree passes isolated and
default-home installation, strict second no-op, 16-file source/staging/live/
archive parity, installed self-test and lifecycle smoke, and focused installed
Stop 1.1 recovery on macOS. A fresh no-bypass task displayed all eight product
Hooks as installed and active and displayed the PostToolUse source as this
plugin with trusted status. Its bounded meta-discussion reply produced
diagnostic `gate_completion_claim` but authoritative
`protocol_default/allow_neutral`, preserved one pending requirement, recorded
zero continuations, and persisted SessionEnd. The host's fresh-task cleanup
removed historical live trees; the safe installer restored them from their
trusted archives, their pre-run content digests remained identical, and the
next apply was a strict no-op. Native Windows diagnosis at clean public head
`2314e2d` confirmed that 0.9.2 constructed and wrote the exact protected
three-entry DACL: the binary header, ACL size, non-null pointer, and successful
native result were consistent, and both `GetAccessRules` and
`RawSecurityDescriptor` read back all three ACEs. The failure was isolated to
PowerShell `.Access` collection enumeration. The consumed 0.9.3 candidate
retained the native write, used both supported readback paths as one strict
contract, passed nine focused Windows tests under a standard user token with
`SeSecurityPrivilege` unavailable, passed its fixed public benchmark 8/8 with
zero false continuations, diagnostic accuracy 1.0, and the reviewed manifest
hash, and passed repository validation, tracked-tree privacy audit, 229 tests
with six capability-aware skips, eight-Hook self-test, Ruff 0.16.1,
external-cache compilation, and diff checks with Python 3.12.10. Its frozen
implementation commit was installed into isolated and default homes, passed
strict second no-op, four-way parity, installed self-test, smoke, and Stop 1.1
recovery, and its first native fresh-Hook run exposed two facts now recorded in
the acceptance document: the bare meta-discussion prompt left the guard
inactive by design, and an isolated byte-level replay proved the runtime
decoded hook stdin with the host ANSI code page, corrupting non-ASCII payload
text before journaling. The 0.9.4 worktree fixes only that transport, adds
subprocess regressions for byte-exact UTF-8 journaling, the UTF-8 Stop decision
contract, and invalid-byte rejection, and leaves every protocol constant
unchanged. Install and fresh-Hook gates remain open for the frozen 0.9.4
commit; CI, tag, and Release acceptance also remain open.

The repository records only sanitized incident IDs, aggregate counts, and the
reviewed public fixture manifest hash. Local corpus location, user identity,
session identifiers, original prompts, credentials, private Hook state, and raw
evidence are never recorded here.

## Open gates

- Freeze the reviewed 0.9.4 implementation commit, then complete install/no-op/
  parity/recovery and fresh-Hook evidence on that exact branch head, with the
  fresh-task prompt explicitly activating the guard.
- Only then proceed through PR/main CI, HOL, annotated tag, tag CI, bilingual
  GitHub Release, and public readback.

## Risks

- Weakening natural-language gates must not weaken privacy, integrity,
  checkpoint authenticity, scope, proof, or explicit user-persistence gates.
- Legacy decision logs must remain readable without allowing a Stop 1.1 staged
  control to become authoritative under Stop 2.0.
- A local incident corpus can leak private evidence if export review or
  filesystem permissions fail; CI therefore consumes only reviewed public
  fixtures and never accesses the private corpus.
- macOS, Windows, CI, installed-cache, and source results can drift independently
  and must remain separately evidenced.

## Exact next entrypoint

From the Windows repository root, run:

```powershell
git diff -- .
```

At the next phase boundary, replace this entrypoint with the first unrun gate
and record the last verified public commit or tree. After publication, keep this
file at the same path, change the status to `Completed`, and link the final
changelog entry, acceptance record, annotated tag, and GitHub Release.
