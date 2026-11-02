# =============================================================================
#  Build script: regenerates the MSI installer for Traceroute
#
#  What it does:
#    1. publishes the utility as a single self-contained traceroute.exe
#    2. runs WiX Toolset to build traceroute.msi (x64, installs to System32)
#
#  Requires the .NET SDK. WiX Toolset (wix) is installed automatically as a
#  .NET global tool if it is not present.
#
#  Usage:   pwsh -File build_msi.ps1
#  Output:  .\traceroute.msi
# =============================================================================
$ErrorActionPreference = 'Stop'

$Root = $PSScriptRoot
Set-Location $Root

# --- 1. make sure WiX Toolset is available --------------------------------
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host 'WiX Toolset not found. Installing as a .NET global tool...'
    dotnet tool install --global wix
    # refresh PATH for this session
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'User') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
}
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Error 'WiX Toolset could not be located. Re-run in a new terminal or add the dotnet tools folder to PATH.'
    exit 1
}

# --- 2. publish the self-contained single-file executable ------------------
Write-Host 'Publishing traceroute (self-contained single file)...'
Remove-Item -Recurse -Force 'publish' -ErrorAction SilentlyContinue
dotnet publish 'traceroute.csproj' -c Release -r win-x64 --self-contained true `
                -p:PublishSingleFile=true -o 'publish' 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Error 'dotnet publish failed.'; exit 1 }
if (-not (Test-Path 'publish\traceroute.exe')) { Write-Error 'publish\traceroute.exe is missing.'; exit 1 }

# --- 3. build the MSI ------------------------------------------------------
Write-Host 'Building traceroute.msi (WiX, x64)...'
Remove-Item 'traceroute.msi' -ErrorAction SilentlyContinue
wix build 'installer.wxs' -arch x64 -o 'traceroute.msi'
if ($LASTEXITCODE -ne 0) { Write-Error 'wix build failed.'; exit 1 }

Write-Host ''
Write-Host ('Done: ' + (Join-Path $Root 'traceroute.msi'))
Write-Host 'Install with (as Administrator):'
Write-Host '    msiexec /i traceroute.msi'
