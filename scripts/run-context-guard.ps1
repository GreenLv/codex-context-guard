$ErrorActionPreference = "Stop"

# Optional native-acceptance trace.  It records only phase, elapsed time and
# exit code in a caller-owned private directory.  Hook stdin, paths, and
# credentials are never written.  An unfinished start record identifies a
# host timeout or process termination before the product could return.
$tracePath = $null
$traceClock = [System.Diagnostics.Stopwatch]::StartNew()
if ($args.Count -gt 0 -and $args[0] -eq "hook" -and $env:CONTEXT_GUARD_HOOK_TRACE_DIR) {
    try {
        $traceDir = [System.IO.Path]::GetFullPath($env:CONTEXT_GUARD_HOOK_TRACE_DIR)
        if ([System.IO.Directory]::Exists($traceDir)) {
            $tracePath = [System.IO.Path]::Combine($traceDir, ([guid]::NewGuid().ToString('N') + '.jsonl'))
            $start = '{"phase":"start","elapsed_ms":0}' + "`n"
            [System.IO.File]::WriteAllText($tracePath, $start, (New-Object System.Text.UTF8Encoding($false)))
        }
    } catch {
        $tracePath = $null
    }
}

function Write-HookTraceEnd([int]$code) {
    if ($tracePath) {
        try {
            $elapsed = [int][Math]::Round($traceClock.Elapsed.TotalMilliseconds)
            $finish = '{"phase":"end","elapsed_ms":' + $elapsed + ',"exit_code":' + $code + '}' + "`n"
            [System.IO.File]::AppendAllText($tracePath, $finish, (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            # Diagnostic I/O must not change the product Hook result.
        }
    }
}

# Phase-2: route the `hook` subcommand through the thin cg_hook.py router;
# all other subcommands use the heavy context_guard.py core.
$isHook = ($args.Count -gt 0 -and $args[0] -eq "hook")
$isSessionEnd = ($args.Count -eq 2 -and $args[0] -eq "hook" -and $args[1] -eq "SessionEnd")
[string[]]$runtimeArgs = if ($isSessionEnd) { @("hook") } else { $args }
if ($isHook -and -not $isSessionEnd) {
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
    # Prefer a verified normal Python before the `py` launcher and the
    # WindowsApps python3 alias. On this host py -3.12 exits 112 despite a
    # working Python 3.12, and the alias can throw during its version probe.
    @{ Command = "python"; Prefix = @(); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.14"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.13"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.12"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.11"); Probe = $true },
    @{ Command = "py"; Prefix = @("-3.10"); Probe = $true },
    @{ Command = "python3"; Prefix = @(); Probe = $true }
)

try {
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
        } catch {
            # A broken optional launcher is a negative probe. Continue to a
            # different interpreter; runtime execution below still fails.
            $probeExitCode = 1
        } finally {
            $ErrorActionPreference = $savedErrorActionPreference
        }
        if ($probeExitCode -ne 0) {
            continue
        }
    }
    if ($isHook -and -not $isSessionEnd) {
        & $resolved.Source @($candidate.Prefix) -S $runtime @runtimeArgs
    } else {
        & $resolved.Source @($candidate.Prefix) $runtime @runtimeArgs
    }
    $hookExitCode = $LASTEXITCODE
    Write-HookTraceEnd $hookExitCode
    exit $hookExitCode
}

[Console]::Error.WriteLine("Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH.")
Write-HookTraceEnd 2
exit 2
} catch {
    Write-HookTraceEnd 1
    throw
}
