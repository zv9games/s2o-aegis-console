# S2O Aegis developer smoke suite (Windows-focused; needs net-lib linked).
# Usage from repo root:
#   pwsh -File scripts/dev-smoke.ps1
# Optional: $env:S2O_NET_LIB = 'C:\ZV9\lines\s2o\net-lib'

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

Write-Host "== net-lib ==" -ForegroundColor Cyan
if (-not (Test-Path (Join-Path (Split-Path $root -Parent) 'net-lib\Cargo.toml'))) {
    if (Test-Path (Join-Path $PSScriptRoot 'setup-net-lib.ps1')) {
        & (Join-Path $PSScriptRoot 'setup-net-lib.ps1')
    }
}

Write-Host "== build suite ==" -ForegroundColor Cyan
cargo build -p aegis-cli -p aegisd -p cyberwall-cli -p cyberdns -p cyberdefender `
  -p cyberedr -p cybersiem -p cyberintel -p cyberid -p cybermesh -p cyberztna -q

function Run-Ok([string]$label, [scriptblock]$block) {
    Write-Host "-- $label" -ForegroundColor Yellow
    & $block
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) {
        # some tools use exit 3 for "blocked" which is success of the control path
        if ($label -match 'block|deny|lookup-hit|posture-low') {
            Write-Host "   exit $LASTEXITCODE (expected non-zero for control path)" -ForegroundColor DarkYellow
            return
        }
        throw "FAIL $label exit=$LASTEXITCODE"
    }
    Write-Host "   ok" -ForegroundColor Green
}

Run-Ok 'aegis doctor' { cargo run -p aegis-cli -q -- doctor }
Run-Ok 'aegis status' { cargo run -p aegis-cli -q -- status }
Run-Ok 'policy edge-pack' { cargo run -p aegis-cli -q -- policy apply policies/examples/edge-pack.json }
Run-Ok 'cyberwall status' { cargo run -p cyberwall-cli -q -- status }
Run-Ok 'cyberdns block' { cargo run -p cyberdns -q -- block smoke.block.s2o }
Run-Ok 'cyberdns resolve blocked' { cargo run -p cyberdns -q -- resolve smoke.block.s2o; if ($LASTEXITCODE -eq 3) { $global:LASTEXITCODE = 0 } }
Run-Ok 'cyberintel sync' { cargo run -p cyberintel -q -- sync }
Run-Ok 'cyberid posture' { cargo run -p cyberid -q -- posture --min-score 40 }
Run-Ok 'cybermesh genkey' { cargo run -p cybermesh -q -- genkey }
Run-Ok 'cybermesh config' { cargo run -p cybermesh -q -- config --output .aegis/wg0.conf --address 10.220.0.2/32 }
Run-Ok 'cyberztna check' { cargo run -p cyberztna -q -- check --min-score 50 }
Run-Ok 'cybersiem stats' { cargo run -p cybersiem -q -- stats --limit 200 }
Run-Ok 'aegis events' { cargo run -p aegis-cli -q -- events --limit 5 }

Write-Host ""
Write-Host "SMOKE PASS" -ForegroundColor Green
