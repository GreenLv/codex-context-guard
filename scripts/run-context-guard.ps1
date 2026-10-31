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
# Every runtime starts with -B so consumed caches do not gain bytecode.
# The stdlib-only Hook router additionally runs with -S (skip site); the
# heavy core and every other CLI subcommand do not.
# Optional interpreter binding: an existing configuration records the verified
# interpreter absolute path in a plain single-line file under the selected
# HOME so a GUI host whose PATH lacks the installed Python still starts the
# Hook. The file is read with plain content (no eval, no profile sourcing)
# and the configured path is invoked directly; an explicit configured path
# that is missing or not executable is an error distinct from "nothing
# configured" and never silently falls back to PATH probing.
$configuredInterpreter = $null
$configRoot = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
$configFile = Join-Path $configRoot "context-guard\interpreter.conf"
if (Test-Path -LiteralPath $configFile -PathType Leaf) {
    try {
        # Existing bindings use BOM-less UTF-8, including non-ASCII paths.
        # PS5.1 Get-Content otherwise guesses the system ANSI code page.
        $configUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $configReader = New-Object System.IO.StreamReader($configFile, $configUtf8, $false)
        try {
            $configuredInterpreter = $configReader.ReadLine()
            # PS5.1 -Encoding UTF8 commonly writes a BOM. Consume exactly
            # that optional UTF-8 prefix without enabling UTF-16/32 encoding
            # detection or weakening the strict UTF-8 decoder above.
            if ($configuredInterpreter -and $configuredInterpreter[0] -eq [char]0xFEFF) {
                $configuredInterpreter = $configuredInterpreter.Substring(1)
            }
        } finally { $configReader.Dispose() }
    } catch {
        [Console]::Error.WriteLine("Context Guard interpreter configuration could not be read as UTF-8: $configFile.")
        Write-HookTraceEnd 2
        exit 2
    }
    if ($configuredInterpreter) {
        $configuredInterpreter = $configuredInterpreter.Trim()
    }
    if ($configuredInterpreter -and -not [System.IO.Path]::IsPathRooted($configuredInterpreter)) {
        [Console]::Error.WriteLine("Context Guard interpreter configuration must contain an absolute path; ignoring $configFile.")
        $configuredInterpreter = $null
    }
}
if ($configuredInterpreter) {
    if (-not (Test-Path -LiteralPath $configuredInterpreter -PathType Leaf)) {
        [Console]::Error.WriteLine("Context Guard interpreter configuration is missing or not executable: $configuredInterpreter. Please review the Context Guard installation in Codex Plugins and the supported Python on PATH, or correct $configFile.")
        Write-HookTraceEnd 2
        exit 2
    }
    if ($isHook) {
        # A replaced or non-Python executable can exit 0 with completely
        # empty output, which would silently skip the Hook. Run the real
        # runtime with stdout captured to a file and verify it produced a
        # Hook wire result before re-emitting it; otherwise fail visibly.
        # Avoid module command discovery in a configured-interpreter launch.
        # GetTempFileName creates the same empty filesystem file atomically.
        $hookOut = [System.IO.FileInfo]([System.IO.Path]::GetTempFileName())
        $savedErrorActionPreference = $ErrorActionPreference
        $savedConsoleInputEncoding = [Console]::InputEncoding
        $savedConsoleOutputEncoding = [Console]::OutputEncoding
        $savedOutputEncoding = $OutputEncoding
        $savedPythonIOEncoding = $env:PYTHONIOENCODING
        try {
            $wireUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
            [Console]::InputEncoding = $wireUtf8
            [Console]::OutputEncoding = $wireUtf8
            $OutputEncoding = $wireUtf8
            $env:PYTHONIOENCODING = "utf-8"
            # Let Python write its own UTF-8 bytes. PS5.1's > writes
            # UTF-16LE, and decoding/re-encoding native stdout can silently
            # damage non-ASCII JSON strings while leaving valid JSON.
            # Preserve script argv and import-path behavior in this process.
            $captureCode = @'
import os, runpy, sys
sys.stdout = open(sys.argv.pop(1), 'w', encoding='utf-8', newline='\n')
target = sys.argv[1]
sys.argv = sys.argv[1:]
sys.path[0] = os.path.dirname(os.path.abspath(target))
runpy.run_path(target, run_name='__main__')
'@
            # A nonzero runtime exit is an expected outcome that must reach
            # the post-verification below, so keep native failures
            # non-terminating inside this capture scope.
            $ErrorActionPreference = "Continue"
            # Native processes update the global automatic variable. A caller
            # invoking this script with & can have a local/script shadow;
            # initialize and read the same global scope on every native call.
            # The nonzero sentinel also refuses a command that never starts.
            $global:LASTEXITCODE = 2
            if (-not $isSessionEnd) {
                $runtimeNoise = & $configuredInterpreter -B -S -c $captureCode $hookOut.FullName $runtime @runtimeArgs
            } else {
                $runtimeNoise = & $configuredInterpreter -B -c $captureCode $hookOut.FullName $runtime @runtimeArgs
            }
            $hookExitCode = $global:LASTEXITCODE
            if ($hookExitCode -eq 0) {
                # Hook wire results are always JSON objects (at minimum "{}").
                # Output shape (first character, brace count) cannot
                # distinguish a working runtime from an unrelated program
                # printing similar text, and "exit 0 with empty output"
                # proves nothing either, so the configured interpreter itself
                # must parse the captured result and print a deterministic
                # marker. Only a program that actually executes the Python
                # json parse and finds a JSON object can emit that marker;
                # empty, incomplete, malformed, non-object, or self-printing
                # programs all fail visibly.
                $wireCode = @'
import json, sys
try:
    payload = json.load(open(sys.argv[1], encoding='utf-8'))
except Exception:
    raise SystemExit(3)
if not isinstance(payload, dict):
    raise SystemExit(4)
print('CG-HOOK-WIRE-VERIFIED')
'@
                $savedWirePreference = $ErrorActionPreference
                try {
                    $ErrorActionPreference = "Continue"
                    $global:LASTEXITCODE = 2
                    $wireNoise = & $configuredInterpreter -I -S -c $wireCode $hookOut.FullName 2>$null
                    $wireExitCode = $global:LASTEXITCODE
                } finally {
                    $ErrorActionPreference = $savedWirePreference
                }
                if ($runtimeNoise -or $wireExitCode -ne 0 -or ((-join $wireNoise) -ne "CG-HOOK-WIRE-VERIFIED")) {
                    [Console]::Error.WriteLine("Context Guard interpreter configuration is not a working Context Guard runtime: $configuredInterpreter produced output that is not a Hook wire result. Please review the Context Guard installation in Codex Plugins and the supported Python on PATH, or correct $configFile.")
                    Write-HookTraceEnd 2
                    exit 2
                }
            }
            [Console]::Out.Write([System.IO.File]::ReadAllText($hookOut.FullName, $wireUtf8))
            Write-HookTraceEnd $hookExitCode
            exit $hookExitCode
        } finally {
            Remove-Item -LiteralPath $hookOut -ErrorAction SilentlyContinue
            $ErrorActionPreference = $savedErrorActionPreference
            $env:PYTHONIOENCODING = $savedPythonIOEncoding
            $OutputEncoding = $savedOutputEncoding
            [Console]::InputEncoding = $savedConsoleInputEncoding
            [Console]::OutputEncoding = $savedConsoleOutputEncoding
        }
    }
    # Non-hook CLI invocations keep the direct call (the operator sees the
    # output directly); hook events took the verified path above.
    $global:LASTEXITCODE = 2
    if (-not $isSessionEnd) {
        & $configuredInterpreter -B -S $runtime @runtimeArgs
    } else {
        & $configuredInterpreter -B $runtime @runtimeArgs
    }
    $hookExitCode = $global:LASTEXITCODE
    Write-HookTraceEnd $hookExitCode
    exit $hookExitCode
}

# Avoid PowerShell's general command discovery for ordinary local PATHs.
# Keep unusual inputs under the original resolver instead of reproducing its
# provider, quote, relative-path or extensionless-file parsing rules.
$pythonPathDirectories = @(([string]$env:PATH).Split([char]';') | Where-Object { $_.Length -gt 0 })
$pythonPathExtensions = ([string]$env:PATHEXT).Split([char]';')
$ordinaryPythonPath = $pythonPathDirectories.Count -gt 0 -and $pythonPathExtensions.Count -gt 0
foreach ($directory in $pythonPathDirectories) {
    if ($directory -notmatch '^[A-Za-z]:[\\/]' -or $directory -match '["<>|?*\x00-\x1f]' -or
        $directory.Substring(2) -match ':' -or $directory -ne $directory.Trim()) {
        $ordinaryPythonPath = $false
    }
}
foreach ($extension in $pythonPathExtensions) {
    if ($extension -notmatch '^\.[A-Za-z0-9]+$') { $ordinaryPythonPath = $false }
}
$pythonLegacyExtensions = @($pythonPathExtensions | Where-Object { $_ -notmatch '^\.(exe|com|cmd|bat)$' })

function Resolve-ContextGuardPythonCommand([string]$Name) {
    if ($Name -match '[\\/:]' -or -not $ordinaryPythonPath -or
        (Test-Path -LiteralPath "Alias:$Name") -or (Test-Path -LiteralPath "Function:$Name")) {
        return (Get-Command $Name -ErrorAction SilentlyContinue)
    }
    # Script and bare-file precedence stays with PowerShell, including .ps1
    # outside PATHEXT. Inspect all directories before choosing an application.
    foreach ($directory in $pythonPathDirectories) {
        if ([System.IO.File]::Exists([System.IO.Path]::Combine($directory, $Name)) -or
            [System.IO.File]::Exists([System.IO.Path]::Combine($directory, $Name + '.ps1'))) {
            return (Get-Command $Name -ErrorAction SilentlyContinue)
        }
        foreach ($extension in $pythonLegacyExtensions) {
            if ([System.IO.File]::Exists([System.IO.Path]::Combine($directory, $Name + $extension))) {
                return (Get-Command $Name -ErrorAction SilentlyContinue)
            }
        }
    }
    foreach ($directory in $pythonPathDirectories) {
        foreach ($extension in $pythonPathExtensions) {
            $file = [System.IO.Path]::Combine($directory, $Name + $extension)
            if ([System.IO.File]::Exists($file)) { return [pscustomobject]@{ Source = $file } }
        }
    }
    return $null
}

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
    $resolved = Resolve-ContextGuardPythonCommand $candidate.Command
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
            $global:LASTEXITCODE = 2
            & $resolved.Source @($candidate.Prefix) -c "import sys; raise SystemExit(sys.version_info < (3, 10))" 2>$null
            $probeExitCode = $global:LASTEXITCODE
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
    $global:LASTEXITCODE = 2
    if ($isHook -and -not $isSessionEnd) {
        & $resolved.Source @($candidate.Prefix) -B -S $runtime @runtimeArgs
    } else {
        & $resolved.Source @($candidate.Prefix) -B $runtime @runtimeArgs
    }
    $hookExitCode = $global:LASTEXITCODE
    Write-HookTraceEnd $hookExitCode
    exit $hookExitCode
}

[Console]::Error.WriteLine("Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH. If a supported Python is installed outside PATH, make Python discoverable to the GUI host or configure interpreter.conf with its absolute path.")
Write-HookTraceEnd 2
exit 2
} catch {
    Write-HookTraceEnd 1
    throw
}
