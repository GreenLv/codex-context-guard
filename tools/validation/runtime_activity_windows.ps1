param([Parameter(Mandatory=$true)][string]$ConfigBase64)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigBase64))
$config = ConvertFrom-Json -InputObject $json
$ignorePids = @($config.ignorePids | ForEach-Object { [int]$_ }) + @([int]$PID)
$targets = @{}
foreach ($slot in @($config.slots)) {
    foreach ($name in @('run_context_guard.sh','run-context-guard.ps1','cg_hook.py','context_guard.py')) {
        $targets[[System.IO.Path]::GetFullPath((Join-Path (Join-Path $slot 'scripts') $name)).ToLowerInvariant()] = $true
    }
}
$inline = @($config.inline)
$currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class CGCommandLineParser {
  [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  private static extern IntPtr CommandLineToArgvW(string command, out int count);
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern IntPtr LocalFree(IntPtr ptr);
  public static string[] Parse(string command) {
    int count; IntPtr ptr = CommandLineToArgvW(command, out count);
    if (ptr == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    try {
      var result = new List<string>();
      for (int i=0;i<count;i++) result.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(ptr, i*IntPtr.Size)));
      return result.ToArray();
    } finally { LocalFree(ptr); }
  }
}
'@

function Is-Target([string]$value) {
    if (-not $value -or -not [System.IO.Path]::IsPathRooted($value)) { return $false }
    try { return $targets.ContainsKey([System.IO.Path]::GetFullPath($value).ToLowerInvariant()) }
    catch { return $false }
}
function Classify-Command([string]$line) {
    $argvParts = @([CGCommandLineParser]::Parse($line))
    if ($argvParts.Count -eq 0) { return 'ambiguous_unreadable_command' }
    if (Is-Target $argvParts[0]) { return 'runtime_script' }
    $head = [System.IO.Path]::GetFileName($argvParts[0]).ToLowerInvariant()
    if ($head -match '^python(?:3(?:\.\d+)?)?(?:\.exe)?$') {
        $idx = 1
        while ($idx -lt $argvParts.Count -and $argvParts[$idx].StartsWith('-')) {
            if ($argvParts[$idx] -eq '-c') {
                if (($idx+3) -lt $argvParts.Count -and (Is-Target $argvParts[$idx+3])) {
                    $code = ($argvParts[$idx+1] -replace "`r`n", "`n").Trim()
                    $known = @'
import os, runpy, sys
sys.stdout = open(sys.argv.pop(1), 'w', encoding='utf-8', newline='\n')
target = sys.argv[1]
sys.argv = sys.argv[1:]
sys.path[0] = os.path.dirname(os.path.abspath(target))
runpy.run_path(target, run_name='__main__')
'@
                    $known = $known.Trim()
                    if ($code -ceq $known) { return 'runtime_python' }
                    if ($code.Contains('runpy') -or $code.Contains('importlib')) { return 'ambiguous_parse' }
                }
                return ''
            }
            if ($argvParts[$idx] -eq '-m') { return '' }
            if ($argvParts[$idx] -in @('-W','-X','--check-hash-based-pycs')) { $idx++ }
            $idx++
        }
        if ($idx -lt $argvParts.Count -and (Is-Target $argvParts[$idx])) { return 'runtime_python' }
        return ''
    }
    if ($head -notin @('powershell.exe','powershell','pwsh.exe','pwsh')) { return '' }
    for ($i=1; $i -lt $argvParts.Count; $i++) {
        if ($argvParts[$i] -in @('-File','-f') -and ($i+1) -lt $argvParts.Count) {
            if (Is-Target $argvParts[$i+1]) { return 'runtime_launcher' }
            return ''
        }
        if ($argvParts[$i] -in @('-Command','-c','-EncodedCommand','-enc','-e')) {
            if (($i+1) -ge $argvParts.Count) { return 'ambiguous_parse' }
            if ($argvParts[$i] -in @('-EncodedCommand','-enc','-e')) {
                try { $body = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($argvParts[$i+1])) }
                catch { return 'ambiguous_parse' }
            } else {
                $body = ($argvParts[($i+1)..($argvParts.Count-1)] -join ' ')
            }
            if ($inline -ccontains $body) { return 'ambiguous_inline_hook_home' }
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
            if ($errors.Count -gt 0) {
                foreach ($slot in @($config.slots)) { if ($body.IndexOf($slot,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return 'ambiguous_parse' } }
                return ''
            }
            $commands = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
            foreach ($command in $commands) {
                if ($command.CommandElements.Count -gt 0) {
                    $name = $command.CommandElements[0].Value
                    if ($name -is [string] -and (Is-Target $name)) { return 'runtime_launcher' }
                    if ($name -is [string] -and ([System.IO.Path]::GetFileName($name) -match '^python(?:3(?:\.\d+)?)?(?:\.exe)?$')) {
                        $elements = @($command.CommandElements | Select-Object -Skip 1)
                        foreach ($element in $elements) {
                            $value = $element.Value
                            if ($value -in @('-c','-m')) { break }
                            if ($value -is [string] -and (Is-Target $value)) { return 'runtime_python' }
                            if ($value -is [string] -and -not $value.StartsWith('-')) { break }
                        }
                    }
                }
            }
            return ''
        }
    }
    return ''
}

$result = New-Object 'System.Collections.Generic.List[object]'
foreach ($row in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
    $processId = [int]$row.ProcessId
    if ($processId -in $ignorePids -or $processId -in @(0,4)) { continue }
    $category = ''
    if ($null -eq $row.CommandLine -or $row.CommandLine -eq '') {
        $image = [string]$row.Name
        if (-not $image -or $image -match '^(python(?:3(?:\.\d+)?)?|powershell|pwsh)(?:\.exe)?$') {
            # Do not attribute a known different user's inaccessible command
            # to this HOME. Unknown ownership remains a blocking candidate.
            $knownOtherOwner = $false
            try {
                $owner = Invoke-CimMethod -InputObject $row -MethodName GetOwnerSid -ErrorAction Stop
                $knownOtherOwner = ($owner.ReturnValue -eq 0 -and $owner.Sid -and $owner.Sid -ne $currentUserSid)
            } catch { }
            if (-not $knownOtherOwner) { $category = 'ambiguous_unreadable_command' }
        }
    } else {
        try { $category = Classify-Command ([string]$row.CommandLine) }
        catch { $category = 'ambiguous_parse' }
    }
    if (-not $category) { continue }
    if ($null -eq $row.CreationDate -or $null -eq $row.ParentProcessId) { throw 'candidate_identity_unavailable' }
    $result.Add(@{pid=$processId; ppid=[int]$row.ParentProcessId;
                  start=([datetime]$row.CreationDate).ToUniversalTime().ToString('o'); category=$category})
}
ConvertTo-Json -InputObject @($result.ToArray()) -Depth 4 -Compress
