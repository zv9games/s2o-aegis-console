# Build release binaries and stage a portable package under dist/.
# Usage (from repo root):
#   pwsh -File scripts/release-package.ps1
#   pwsh -File scripts/release-package.ps1 -SkipBuild
#   pwsh -File scripts/release-package.ps1 -Version 0.2.0

param(
    [string]$Version = "",
    [switch]$SkipBuild,
    [string]$OutDir = ""
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

if (-not $Version) {
    $Version = (Get-Date -Format 'yyyy.MM.dd')
}
if (-not $OutDir) {
    $OutDir = Join-Path $root "dist\s2o-aegis-$Version-windows-x64"
}

$bins = @(
    'aegisd', 'aegis', 'cyberwall', 'cyberdns', 'cyberdefender', 'cyberedr',
    'cybersiem', 'cyberintel', 'cyberid', 'cybermesh', 'cyberztna'
)

Write-Host "== release package $Version ==" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "== cargo build --release ==" -ForegroundColor Cyan
    $pkgs = $bins | ForEach-Object {
        if ($_ -eq 'aegis') { '-p'; 'aegis-cli' }
        elseif ($_ -eq 'cyberwall') { '-p'; 'cyberwall-cli' }
        else { '-p'; $_ }
    }
    # flatten
    $args = @('build', '--release') + ($bins | ForEach-Object {
        if ($_ -eq 'aegis') { @('-p', 'aegis-cli') }
        elseif ($_ -eq 'cyberwall') { @('-p', 'cyberwall-cli') }
        else { @('-p', $_) }
    } | ForEach-Object { $_ })
    & cargo @args
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

$target = Join-Path $root 'target\release'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$binDir = Join-Path $OutDir 'bin'
$docDir = Join-Path $OutDir 'docs'
$polDir = Join-Path $OutDir 'policies\examples'
$scrDir = Join-Path $OutDir 'scripts'
New-Item -ItemType Directory -Force -Path $binDir, $docDir, $polDir, $scrDir | Out-Null

$manifest = @()
foreach ($b in $bins) {
    $src = Join-Path $target "$b.exe"
    if (-not (Test-Path $src)) {
        Write-Host "  skip missing $b.exe" -ForegroundColor Yellow
        continue
    }
    $dst = Join-Path $binDir "$b.exe"
    Copy-Item $src $dst -Force
    $h = (Get-FileHash $dst -Algorithm SHA256).Hash.ToLowerInvariant()
    $len = (Get-Item $dst).Length
    $manifest += [pscustomobject]@{ name = "$b.exe"; sha256 = $h; bytes = $len }
    Write-Host "  packaged $b.exe ($len bytes)" -ForegroundColor Green
}

foreach ($f in @('README.md', 'CHANGELOG.md', 'LICENSE', 'LICENSE.md')) {
    $p = Join-Path $root $f
    if (Test-Path $p) { Copy-Item $p (Join-Path $OutDir (Split-Path $f -Leaf)) -Force }
}
foreach ($f in @('OPERATOR.md', 'ROADMAP.md', 'OS_MATRIX.md', 'BUILD.md')) {
    $p = Join-Path $root "docs\$f"
    if (Test-Path $p) { Copy-Item $p (Join-Path $docDir $f) -Force }
}
if (Test-Path (Join-Path $root 'policies\examples')) {
    Copy-Item (Join-Path $root 'policies\examples\*') $polDir -Force
}
foreach ($f in @('install-aegis-tools.ps1', 'install-aegis-service.ps1', 'dev-smoke.ps1', 's2o-aegisd.service')) {
    $p = Join-Path $root "scripts\$f"
    if (Test-Path $p) { Copy-Item $p (Join-Path $scrDir $f) -Force }
}

$readme = @"
# S2O Aegis $Version (Windows x64)

## Quick start

``````powershell
# Optional: add bin to PATH for this session
`$env:Path = "`$(Join-Path `$PSScriptRoot 'bin');`$env:Path"

# Bootstrap lab data + suite-lab policy
.\bin\aegis.exe setup --policy suite --enroll-fleet --json

# Doctor / selftest
.\bin\aegis.exe doctor --json
.\bin\aegis.exe selftest --json

# Fleet day-2 (with aegisd running on :9090)
.\bin\aegisd.exe start --health-bind 127.0.0.1:9090
.\bin\aegis.exe fleet sync --json
``````

## Service install (Administrator)

``````powershell
pwsh -File .\scripts\install-aegis-tools.ps1 -Release -RegisterService
# or: .\bin\aegis.exe service install --json
``````

## SHA-256

See MANIFEST.json in this directory.
"@
Set-Content -Path (Join-Path $OutDir 'PACKAGE.md') -Value $readme -Encoding UTF8

$meta = [ordered]@{
    name        = 's2o-aegis'
    version     = $Version
    platform    = 'windows-x64'
    built_at    = (Get-Date).ToUniversalTime().ToString('o')
    binaries    = $manifest
}
$meta | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'MANIFEST.json') -Encoding UTF8

Write-Host ""
Write-Host "Package staged: $OutDir" -ForegroundColor Green
Write-Host "  binaries: $($manifest.Count)" -ForegroundColor Green
Write-Host "  manifest: MANIFEST.json" -ForegroundColor Green
