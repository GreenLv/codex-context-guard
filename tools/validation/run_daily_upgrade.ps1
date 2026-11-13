# PowerShell thin launcher for the daily-upgrade entry.
#
# Supported runtime: Windows PowerShell 5.1 and PowerShell 7 (pwsh). The
# syntax below deliberately avoids PowerShell-7-only operators (ternary, null
# coalescing) so one script serves both shells. The POSIX twin is
# run_daily_upgrade.sh; both exec the same testable Python core with
# passthrough arguments, so either shell starts exactly one Python process
# and stdout/stderr/stdin keep the tool wire contract.
#
# Usage: run_daily_upgrade.ps1 -Target daily [-Arguments @("--plan", ...)]
#
# Every runtime starts with -B so the source checkout stays free of bytecode.
# A missing or refused interpreter exits 2 with an actionable message and
# never falls back to a random command.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("daily", "print-argv")]
    [string]$Target,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments = @()
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Real-entry probe mode: echoes the parsed argument vector as JSON and
# exits 0 without touching any target.
if ($Target -eq "print-argv") {
    ConvertTo-Json -InputObject @("print-argv", $Arguments) -Compress
    exit 0
}

$targetPath = Join-Path $scriptDir "daily_upgrade.py"
if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
    Write-Error "daily upgrade target module is missing: $targetPath"
    exit 2
}

function Test-PythonRuntime {
    param([string]$Path, [string[]]$InterpreterArgs)
    # Windows PowerShell 5.1 strips embedded double quotes in native arguments.
    $probe = & $Path @InterpreterArgs -B -I -S -c @'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(2)
print('CG-PYTHON-3.10-RUNTIME-VERIFIED')
'@ 2>$null
    return ("$probe".Trim() -eq "CG-PYTHON-3.10-RUNTIME-VERIFIED")
}

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
    if (-not (Test-PythonRuntime -Path $resolved.Source -InterpreterArgs $resolvedArgs)) { continue }
    & $resolved.Source @resolvedArgs -B $targetPath @Arguments
    exit $LASTEXITCODE
}

[Console]::Error.WriteLine("The daily-upgrade entry requires Python 3.10 or newer, but no " +
    "supported interpreter was found on PATH. Make a supported Python " +
    "discoverable to this shell and retry.")
exit 2
