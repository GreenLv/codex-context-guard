$ErrorActionPreference = "Stop"

$runtime = Join-Path $PSScriptRoot "context_guard.py"
$candidates = @(
    @{ Command = "python"; Prefix = @() },
    @{ Command = "python3"; Prefix = @() },
    @{ Command = "python3.14"; Prefix = @() },
    @{ Command = "python3.13"; Prefix = @() },
    @{ Command = "python3.12"; Prefix = @() },
    @{ Command = "python3.11"; Prefix = @() },
    @{ Command = "python3.10"; Prefix = @() },
    @{ Command = "py"; Prefix = @("-3.14") },
    @{ Command = "py"; Prefix = @("-3.13") },
    @{ Command = "py"; Prefix = @("-3.12") },
    @{ Command = "py"; Prefix = @("-3.11") },
    @{ Command = "py"; Prefix = @("-3.10") }
)

foreach ($candidate in $candidates) {
    $resolved = Get-Command $candidate.Command -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        continue
    }
    & $resolved.Source @($candidate.Prefix) -c "import sys; raise SystemExit(sys.version_info < (3, 10))" 2>$null
    if ($LASTEXITCODE -eq 0) {
        & $resolved.Source @($candidate.Prefix) $runtime @args
        exit $LASTEXITCODE
    }
}

[Console]::Error.WriteLine("Context Guard requires Python 3.10 or newer, but no supported interpreter was found on PATH.")
exit 2
