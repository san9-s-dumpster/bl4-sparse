# Runs entirely locally. Does not install Python or change execution policy.
[CmdletBinding()]
param(
    [ValidateSet('Interactive', 'Audit', 'Restore')]
    [string]$Mode = 'Interactive'
)

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'bl4_sparse.py'
$runtime = $null
$runtimeArgs = @()
$candidates = @(
    @{ Name = 'py'; Arguments = @('-3') },
    @{ Name = 'python'; Arguments = @() },
    @{ Name = 'python3'; Arguments = @() }
)

foreach ($candidate in $candidates) {
    $command = Get-Command $candidate.Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) { continue }
    # Avoid Windows Store aliases, which may open the Store instead of Python.
    if ($command.Source -like '*\Microsoft\WindowsApps\*') { continue }
    $probeArgs = @($candidate.Arguments) + @(
        '-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    )
    try {
        & $command.Source @probeArgs 2>$null
        if ($LASTEXITCODE -eq 0) {
            $runtime = $command.Source
            $runtimeArgs = @($candidate.Arguments)
            break
        }
    } catch {
        continue
    }
}

if ($null -eq $runtime) {
    Write-Error 'Python 3.10 or newer is required. Install Python, reopen PowerShell, and try again.'
    exit 1
}

$modeArgs = @()
if ($Mode -eq 'Audit') { $modeArgs = @('audit') }
if ($Mode -eq 'Restore') { $modeArgs = @('restore') }
& $runtime @runtimeArgs $scriptPath @modeArgs
exit $LASTEXITCODE
