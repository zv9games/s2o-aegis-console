# Install S2O Aegis suite binaries to a local tools directory and register
# a logon Scheduled Task for aegisd (not a full Windows Service - T0).
#
# Usage (from repo root, after cargo build --release preferred):
#   pwsh -File scripts/install-aegis-tools.ps1
#   pwsh -File scripts/install-aegis-tools.ps1 -Release
#   pwsh -File scripts/install-aegis-tools.ps1 -RegisterTask

param(
    [switch]$Release,
    [switch]$RegisterTask,
    [string]$InstallDir = "$env:LOCALAPPDATA\S2O\Aegis\bin"
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$profile = if ($Release) { 'release' } else { 'debug' }
$target = Join-Path $root "target\$profile"

if (-not (Test-Path (Join-Path $target 'aegisd.exe'))) {
    Write-Host "Building $profile suite binaries..." -ForegroundColor Cyan
    if ($Release) {
        cargo build --release -p aegisd -p aegis-cli -p cyberwall-cli -p cyberdns `
          -p cyberdefender -p cyberedr -p cybersiem -p cyberintel -p cyberid `
          -p cybermesh -p cyberztna
    } else {
        cargo build -p aegisd -p aegis-cli -p cyberwall-cli -p cyberdns `
          -p cyberdefender -p cyberedr -p cybersiem -p cyberintel -p cyberid `
          -p cybermesh -p cyberztna
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$bins = @(
    'aegisd','aegis','cyberwall','cyberdns','cyberdefender','cyberedr',
    'cybersiem','cyberintel','cyberid','cybermesh','cyberztna'
)
foreach ($b in $bins) {
    $src = Join-Path $target "$b.exe"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $InstallDir "$b.exe") -Force
        Write-Host "  installed $b.exe" -ForegroundColor Green
    } else {
        Write-Host "  skip missing $b.exe" -ForegroundColor Yellow
    }
}

# Ensure user PATH includes install dir for this session note
Write-Host ""
Write-Host "Install dir: $InstallDir" -ForegroundColor Cyan
Write-Host "Add to User PATH if needed:" -ForegroundColor Cyan
Write-Host "  [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'User')"

$data = Join-Path $env:LOCALAPPDATA 'S2O\Aegis\data'
New-Item -ItemType Directory -Force -Path $data | Out-Null
Write-Host "Data dir (suggested): $data" -ForegroundColor Cyan

if ($RegisterTask) {
    $aegisd = Join-Path $InstallDir 'aegisd.exe'
    if (-not (Test-Path $aegisd)) { throw "aegisd.exe not installed" }
    $action = New-ScheduledTaskAction -Execute $aegisd -Argument "start --event-log `"$data\events.jsonl`"" -WorkingDirectory $data
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'S2O-Aegisd' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Host "Registered Scheduled Task: S2O-Aegisd (AtLogOn)" -ForegroundColor Green
    Write-Host "Start now: Start-ScheduledTask -TaskName S2O-Aegisd"
} else {
    Write-Host "Tip: re-run with -RegisterTask to auto-start aegisd at logon" -ForegroundColor DarkYellow
}

Write-Host "Done." -ForegroundColor Green
