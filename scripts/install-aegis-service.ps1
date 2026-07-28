# Register aegisd as a real Windows Service (SCM) — requires Administrator.
# Prefer:  cargo run -p aegis-cli -- service install
# Or this script after tools are installed.
#
# Usage:
#   pwsh -File scripts/install-aegis-service.ps1
#   pwsh -File scripts/install-aegis-service.ps1 -BinPath "C:\...\aegisd.exe" -Start
#   pwsh -File scripts/install-aegis-service.ps1 -Uninstall

param(
    [string]$ServiceName = "S2OAegisd",
    [string]$BinPath = "",
    [string]$DataDir = "$env:LOCALAPPDATA\S2O\Aegis\data",
    [string]$HealthBind = "127.0.0.1:9090",
    [switch]$Start,
    [switch]$Uninstall,
    [switch]$AlsoTask
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')

if ($Uninstall) {
    sc.exe stop $ServiceName 2>$null | Out-Null
    sc.exe delete $ServiceName
    if ($AlsoTask) {
        schtasks /Delete /TN "S2O-Aegisd" /F 2>$null | Out-Null
    }
    Write-Host "Removed service $ServiceName" -ForegroundColor Yellow
    exit 0
}

if (-not $BinPath) {
    foreach ($cand in @(
        (Join-Path $root "target\release\aegisd.exe"),
        (Join-Path $root "target\debug\aegisd.exe"),
        (Join-Path $env:LOCALAPPDATA "S2O\Aegis\bin\aegisd.exe")
    )) {
        if (Test-Path $cand) { $BinPath = $cand; break }
    }
}
if (-not $BinPath -or -not (Test-Path $BinPath)) {
    throw "aegisd.exe not found. Build with: cargo build -p aegisd  (or pass -BinPath)"
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$eventLog = Join-Path $DataDir "events.jsonl"
# Entire service command is one binPath= value (quote paths only if they contain spaces)
function Quote-IfNeeded([string]$p) {
    if ($p -match '\s') { return ('\"{0}\"' -f $p) }
    return $p
}
$binArg = "{0} --run-as-service --event-log {1} --health-bind {2}" -f `
    (Quote-IfNeeded $BinPath), (Quote-IfNeeded $eventLog), $HealthBind

Write-Host "Service : $ServiceName" -ForegroundColor Cyan
Write-Host "binPath : $binArg" -ForegroundColor Cyan

# sc.exe requires space after '=' — route through cmd /C as one line
$createCmd = 'sc.exe create "{0}" binPath= "{1}" start= auto DisplayName= "S2O Aegis Suite Kernel (aegisd)"' -f $ServiceName, $binArg
cmd.exe /C $createCmd
if ($LASTEXITCODE -ne 0) {
    throw "sc create failed (need Administrator?). exit=$LASTEXITCODE"
}
sc.exe description $ServiceName "S2O Aegis control plane: health HTTP, status matrix, event store" | Out-Null

if ($AlsoTask) {
    $tr = "`"$BinPath`" start --event-log `"$eventLog`" --health-bind $HealthBind"
    schtasks /Create /TN "S2O-Aegisd" /SC ONLOGON /RL LIMITED /F /TR $tr | Out-Null
    Write-Host "Also registered Scheduled Task S2O-Aegisd" -ForegroundColor Green
}

if ($Start) {
    sc.exe start $ServiceName
    Write-Host "Started $ServiceName" -ForegroundColor Green
} else {
    Write-Host "Installed. Start with: sc start $ServiceName   or   aegis service start" -ForegroundColor Green
}
