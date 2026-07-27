# Link s2o_net_lib next to this workspace so Cargo path deps resolve.
# Usage (from repo root):  pwsh -File scripts/setup-net-lib.ps1
# Optional:  $env:S2O_NET_LIB = 'D:\path\to\net-lib'

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$parent = Split-Path $repoRoot -Parent
$linkPath = Join-Path $parent 'net-lib'

$candidates = @()
if ($env:S2O_NET_LIB) { $candidates += $env:S2O_NET_LIB }
$candidates += @(
    'C:\ZV9\lines\s2o\net-lib',
    (Join-Path $parent 'lines\s2o\net-lib'),
    (Join-Path (Split-Path $parent -Parent) 'lines\s2o\net-lib')
)

$source = $null
foreach ($c in $candidates) {
    if ($c -and (Test-Path (Join-Path $c 'Cargo.toml'))) {
        $source = (Resolve-Path $c).Path
        break
    }
}

if (-not $source) {
    Write-Error @"
Could not find s2o_net_lib (net-lib crate).

Set S2O_NET_LIB to the net-lib directory, or place it at:
  C:\ZV9\lines\s2o\net-lib

Expected Cargo.toml inside that folder.
"@
}

if (Test-Path $linkPath) {
    $item = Get-Item $linkPath -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Write-Host "OK: junction already exists at $linkPath"
        Write-Host " -> $((Get-Item $linkPath).Target -join ', ')"
        exit 0
    }
    Write-Error "Path exists and is not a junction: $linkPath — move/rename it, then re-run."
}

New-Item -ItemType Junction -Path $linkPath -Target $source | Out-Null
Write-Host "Created junction:"
Write-Host "  $linkPath"
Write-Host "  -> $source"
Write-Host "Verify: cargo check -p cyberwall-backend-windows"
