$ErrorActionPreference = "Stop"

# Phase-2: route the `hook` subcommand through the thin cg_hook.py router;
# all other subcommands use the heavy context_guard.py core.
$isHook = ($args.Count -gt 0 -and $args[0] -eq "hook")
if ($isHook) {
    $runtime = Join-Path $PSScriptRoot "cg_hook.py"
} else {
    $runtime = Join-Path $PSScriptRoot "context_guard.py"
}

# Version-pinned command names (python3.10..python3.14) satisfy the >=3.10
# floor by name, so resolving the command is enough and the Hook hot path
# starts Python exactly once. The `py` launcher takes its version from
# arguments and the generic `python`/`python3` names say nothing about the
# version, so those candidates keep a capability probe for equivalent safety.
# The stdlib-only Hook router additionally runs with -S (skip site); the
# heavy core and every other CLI subcommand do not.
$candidates = @(
    @{ Command = "python3.14"; Prefix = @(); Probe = $false },
    @{ Command = "python3.13"; Prefix = @(); Probe = $false },
    @{ Command = "python3.12"; Prefix = @(); Probe = $false },
    @{ Command = "python3.11"; Prefix = @(); Probe = $false },
    @{ Command = "python3.10"; Prefix = @(); Probe = $false },
    @{ Command = "py"; Prefix = @("-3.14"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.13"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.12"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.11"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.10"); Probe = $true },
    @{ Command = "python3"; Prefix = @(); Probe = $true },
    @{ Command = "python"; Prefix = @(); Probe = $true }
)

foreach ($candidate in $candidates) {
    $resolved = Get-Command $candidate.Command -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        continue
    }
    if ($candidate.Probe) {
        # A missing `py -3.x` runtime is an expected negative probe, not a
        # launcher failure.  PowerShell 7 can promote a non-zero native exit
        # to an ErrorRecord when PSNativeCommandUseErrorActionPreference is
        # enabled; temporarily keep that probe non-terminating so the next
        # candidate is still considered.  Runtime execution below retains the
        # script-wide Stop policy.
        $savedErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & $resolved.Source @($candidate.Prefix) -c "import sys; raise SystemExit(sys.version_info < (3, 10))" 2>$null
            $probeExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorActionPreference
        }
        if ($probeExitCode -ne 0) {
            continue
        }
    }
    if ($isHook) {
        & $resolved.Source @($candidate.Prefix) -S $runtime @args
    } else {
        & $resolved.Source @($candidate.Prefix) $runtime @args
    }
    exit $LASTEXITCODE
}

[Console]::Error.WriteLine("Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH.")
exit 2
