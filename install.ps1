# =============================================================================
#  Traceroute installer for Windows
#
#  Builds the traceroute utility as a single self-contained executable and
#  installs it into C:\Windows\System32, so it can be run from anywhere as:
#      traceroute <host>
#
#  Writing to System32 requires Administrator rights; this script relaunches
#  itself elevated (UAC prompt) when needed.
# =============================================================================

$ErrorActionPreference = 'Stop'

$Root      = $PSScriptRoot                       # ...\TracerouteWin\Projects
$Project   = Join-Path $Root 'traceroute.csproj'
$Publish   = Join-Path $Root 'publish'
$Target    = Join-Path $env:SystemRoot 'System32\traceroute.exe'

# ----------------------------------------------------------------------------
# 1. Elevate to Administrator if needed
# ----------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
                [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This installation requires Administrator rights. Requesting elevation (UAC)...'
    Write-Host ''
    # locate a PowerShell host for the elevated relaunch (pwsh or Windows PowerShell)
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    $runner = if ($pwsh) { $pwsh.Source }
              else { Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process $runner -Verb RunAs -ArgumentList $argList -Wait
    Write-Host 'Installation finished (in the elevated window).'
    exit
}

# ----------------------------------------------------------------------------
# 2. Check prerequisites
# ----------------------------------------------------------------------------
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error 'The .NET SDK (dotnet) was not found. Install it from https://dotnet.microsoft.com and re-run.'
    exit 1
}
if (-not (Test-Path $Project)) {
    Write-Error "Project not found: $Project"
    exit 1
}

# ----------------------------------------------------------------------------
# 3. Build the utility as a single, self-contained executable
# ----------------------------------------------------------------------------
Write-Host ''
Write-Host 'Building traceroute (self-contained single file)...'
Remove-Item -Recurse -Force $Publish -ErrorAction SilentlyContinue
dotnet publish $Project -c Release -r win-x64 --self-contained true `
                -p:PublishSingleFile=true -o $Publish | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Error 'dotnet publish failed.'
    exit 1
}

$exe = Join-Path $Publish 'traceroute.exe'
if (-not (Test-Path $exe)) {
    Write-Error "Build produced no traceroute.exe in $Publish"
    exit 1
}

# ----------------------------------------------------------------------------
# 4. Install into System32
# ----------------------------------------------------------------------------
Write-Host ''
Write-Host "Installing traceroute into:"
Write-Host "  $Target"
Copy-Item -Path $exe -Destination $Target -Force

# ----------------------------------------------------------------------------
# 5. Verify
# ----------------------------------------------------------------------------
Write-Host ''
Write-Host 'Installed successfully. Verification:'
& $Target --version
Write-Host ''
Write-Host 'You can now run from anywhere:  traceroute <host>'
Write-Host ''
Read-Host 'Press Enter to close'
