# PowerShell thin launcher for the native acceptance toolkit.
#
# Supported runtime: Windows PowerShell 5.1 and PowerShell 7 (pwsh). The syntax
# below deliberately avoids PowerShell-7-only operators (ternary, null
# coalescing) so one script serves both shells. The POSIX twin is
# run_native_acceptance.sh; both exec the same testable Python cores with
# passthrough arguments, so either shell starts exactly one Python process and
# stdout/stderr/stdin keep the tool wire contract.
#
# Usage: run_native_acceptance.ps1 -Target {upgrade|acceptance|retention|scheduler} [-Arguments @("-preflight", ...)]
#   upgrade    tools/validation/native_upgrade_acceptance.py
#   acceptance tools/validation/native_acceptance.py (host/retention/scheduler batches)
#   retention  tools/validation/windows_retention_native.py
#   scheduler  tools/validation/native_scheduler_batch.py
#
# Every runtime starts with -B so the source checkout and installed roots stay
# free of bytecode. A missing or refused interpreter exits 2 with an actionable
# message and never falls back to a random command.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("upgrade", "acceptance", "retention", "scheduler")]
    [string]$Target,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments = @()
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$targets = @{
    upgrade    = "native_upgrade_acceptance.py"
    acceptance = "native_acceptance.py"
    retention  = "windows_retention_native.py"
    scheduler  = "native_scheduler_batch.py"
}
$targetPath = Join-Path $scriptDir $targets[$Target]
if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
    Write-Error "native acceptance target module is missing: $targetPath"
    exit 2
}

function Test-PythonRuntime {
    param([string]$Path)
    $probe = & $Path -B -I -S -c @'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(2)
print("CG-PYTHON-3.10-RUNTIME-VERIFIED")
'@ 2>$null
    return ("$probe".Trim() -eq "CG-PYTHON-3.10-RUNTIME-VERIFIED")
}

$genericCandidates = @()
foreach ($versioned in @("python3.14", "python3.13", "python3.12",
                         "python3.11", "python3.10")) {
    $resolved = Get-Command $versioned -ErrorAction SilentlyContinue
    if ($null -ne $resolved) {
        & $resolved.Source -B $targetPath @Arguments
        exit $LASTEXITCODE
    }
}
foreach ($generic in @("python3", "python", "py")) {
    $resolved = Get-Command $generic -ErrorAction SilentlyContinue
    if ($null -eq $resolved) { continue }
    if ($generic -eq "py") {
        # The Windows launcher resolves the newest installed 3.x it controls;
        # only accept it when it actually provides Python 3.10+.
        $resolvedArgs = @("-3")
    }
    else {
        $resolvedArgs = @()
    }
    if (-not (Test-PythonRuntime -Path $resolved.Source)) { continue }
    & $resolved.Source @resolvedArgs -B $targetPath @Arguments
    exit $LASTEXITCODE
}

[Console]::Error.WriteLine ("The native acceptance toolkit requires Python 3.10 or newer, but no " +
    "supported interpreter was found on PATH. Make a supported Python " +
    "discoverable to this shell and retry.")
exit 2
