# Windows retention native acceptance

This tool checks four filesystem conditions in private synthetic fixtures.
Pure consumer/path tests are separate from native acceptance; only an executed
result with its bound product, toolkit, artifact and platform identities can
establish that acceptance. Run a clean committed toolkit checkout. Do not edit
the frozen product checkout or an installed plugin cache.

## Subject and result

`windows_retention_native.py` implements `cg-windows-retention-native/v1`, four
synthetic-root cases, `--preflight` and `--verify-result`. It loads the checked
**installed** `scripts/context_guard.py`; it does not use a test fixture's global
source runtime. Required product source is
`daff36e8b7855b0c16962f18a419fcb9fca50109`, runtime digest
`31399e314f38fb265f2a679a086782bdb17a379c458a64b72dca9951638104de`.

Bindings include toolkit commit and disk bytes of this module and the existing
`incident_readonly_child.py`, the source artifact-identity helper, canonical inner
ZIP SHA/size/contents, exact installed distribution and runtime, Python program
identity, installation path, and the selected fixture path. Importing helpers
and running scenes disable bytecode writes; bindings are checked again afterward.
The verifier recomputes subject bindings and per-object conditions, rejecting a
missing/duplicate case, capability skip, incomplete cleanup, numeric type
confusion, changed object/ledger, missing candidate report or missing positive
control. Recorded JSON is not an authentication/provenance mechanism: arbitrary
caller-authored JSON does not establish an observed native run.

Four cases:

1. **DACL refusal.** A pinned, self-owned synthetic `state.json` receives one
   actual deny-READ_DATA ACE. A real file read must return WinError 5, and the
   actual retention report must name `candidate:state_unreadable`. The original
   DACL is restored through its original file handle, with descriptor-contract
   readback and handle closure in `finally`. The original descriptor is kept in
   an ACL-private recovery sidecar in the fixture. No owner/group/SACL change or
   privilege request is made. A cleanup error remains failed and retains both
   the primary observation and recovery information.
2. **No DELETE sharing.** A real `CreateFileW` directory handle uses share mode
   3 (READ|WRITE, no DELETE). An independent non-mutating DELETE-access open
   must return WinError 32; retention must report `candidate:quarantine_failed`.
   Handle identity and closure are recorded. This is separate from msvcrt locks.
3. **Case alias.** The actual original and uppercase data-directory strings
   must identify the same directory by native handle identity. The alias string
   is passed unchanged to retention while a real lifecycle lock protects the
   candidate; its report must name `busy_lock`. Release precedes normal progress.
   A case-sensitive directory that does not provide this alias is unavailable.
4. **Long payload.** A real ordinary absolute payload path exceeds 300 characters
   with components under 255. An explicitly verified unfinished candidate stays
   protected. Its payload is read after protection and after quarantine/restore;
   exact digests must match. It is then purged by a normal strong identity. This
   proposal tests ordinary absolute paths only; extended-prefix paths are not
   claimed. It never changes LongPathsEnabled, registry, PATH or host policy.

Every case preserves a separate unfinished guard and reads it through the
official reader. Once the condition is released, the same candidate must
quarantine, explicitly restore, read back its original identity and five-field
ledger, then quarantine and purge with its birth identity. The long-path case
explicitly completes its own synthetic obligations before that positive control.
Purge is called with a declared synthetic adjudication timestamp of current UTC
plus eight days, under the real maintenance lock and real 20-second deadline.
It does **not** patch the OS clock, mock OS return values, test real scheduling,
or claim elapsed grace-period observation. Product filesystem calls themselves
remain synchronous, as in the owning runtime; the deadline is not a preemption
guarantee for blocking Windows APIs.

## Paths and invocation (PowerShell 5.1+)

Use the existing Python 3.10+ interpreter; no tool installation is necessary.
All paths are absolute. `$ccgPrivateParent` and the output's parent must already
be ordinary directories owned by the current user with only current-user and
SYSTEM FullControl ACEs. Unsupported descriptors are refused. Product-created
fixture children retain the product's own private-directory contract. Fixtures
and raw observations contain synthetic content, never authentication material.

Protected-root, lexical reparse and native final-path checks precede creation.
SUBST/8.3/device aliases that cannot be proven from the ordinary final spelling
are refused. Relevant existing roots are pinned against replacement during the
batch. The fixture is a new direct child; output and its event sidecar must be
new and outside the fixture, source trees, installation, ZIP, default Codex HOME,
and all explicitly protected roots. Include **every authenticated acceptance
HOME** in `--protected-root`; the tool never reads those HOME contents.

```powershell
$ccgPython = '<verified existing Python executable>'
# Supply reviewed, frozen paths and the canonical CI inner-ZIP SHA.
$ccgArgs = @(
  (Join-Path $ccgToolRepo 'tools\validation\windows_retention_native.py'),
  '--tool-repo-root', $ccgToolRepo, '--tool-commit', $ccgToolCommit,
  '--product-repo-root', $ccgProductRepo,
  '--installed-plugin-root', $ccgInstalledPlugin,
  '--release-zip', $ccgCanonicalInnerZip,
  '--release-zip-sha256', $ccgCanonicalInnerZipSha,
  '--private-parent', $ccgPrivateParent,
  '--protected-root', $ccgAuthenticatedHome,
  '--fixture-root', $ccgNewFixture,
  '--output', $ccgNewResult
)
& $ccgPython -B @ccgArgs --preflight
if ($LASTEXITCODE -ne 0) { throw 'Preflight did not pass' }
& $ccgPython -B @ccgArgs
# Read terminal JSON and exit code; preserve failed/incomplete evidence.
```

Preflight performs a short exclusive write/flush/delete probe only after all
path/private checks, and creates neither the fixture nor final result. To consume
the result independently, reuse the same trusted identity/path arguments and
replace `--output $ccgNewResult` with `--verify-result $ccgNewResult`.

Exit 0 means all four observed scenarios and the consumer passed. Exit 1 is an
executed failure, exit 2 refuses an input/binding, and exit 3 means a required
capability is unavailable or the batch remains incomplete. A protected object is
not a deleted object, and unavailable is never pass. Stop after a real product
counterexample; do not enlarge budgets or weaken an oracle. Resource cleanup
failure is failed. Fixtures, output and event sidecars are deliberately retained;
there is no recursive cleanup, cache repair, authentication copy, account change,
publication or consumer-pin mutation in this module.

## Focused checks

```powershell
& $ccgPython -B tests\test_windows_retention_native.py -v
```

These controls use synthetic recorded facts and temporary ordinary paths only.
They exercise consumer acceptance/rejection and write-before-guard prevention;
they do not mock Windows APIs to manufacture native acceptance. Run the real
preflight/scenes only in a separately authorized batch after toolkit commit and
canonical artifact/installation identities are available.
