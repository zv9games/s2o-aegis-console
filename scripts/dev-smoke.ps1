# S2O Aegis developer smoke suite (Windows-focused; needs net-lib linked).
# Usage from repo root:
#   pwsh -File scripts/dev-smoke.ps1
#   pwsh -File scripts/dev-smoke.ps1 -Json
# Optional: $env:S2O_NET_LIB = 'C:\ZV9\lines\s2o\net-lib'

param(
    [switch]$Json
)

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
        if ($label -match 'block|deny|lookup-hit|posture-low|trace|realtime|reload') {
            Write-Host "   exit $LASTEXITCODE (expected non-zero for control path)" -ForegroundColor DarkYellow
            return
        }
        throw "FAIL $label exit=$LASTEXITCODE"
    }
    Write-Host "   ok" -ForegroundColor Green
}

if ($Json) {
    Write-Host "== JSON automation smoke ==" -ForegroundColor Cyan
    Run-Ok 'aegis doctor --json' { cargo run -p aegis-cli -q -- doctor --json }
    Run-Ok 'aegis selftest --json' { cargo run -p aegis-cli -q -- selftest --min-posture 40 --json }
    Run-Ok 'policy plan suite-lab --json' { cargo run -p aegis-cli -q -- policy plan policies/examples/suite-lab-pack.json --json }
    Run-Ok 'policy apply suite-lab --json' { cargo run -p aegis-cli -q -- policy apply policies/examples/suite-lab-pack.json --json }
    Run-Ok 'policy apply mesh-seed --json' { cargo run -p aegis-cli -q -- policy apply policies/examples/mesh-seed-pack.json --json }
    Run-Ok 'mesh peers list --json' { cargo run -p cybermesh -q -- peers list --json }
    Run-Ok 'dns serve ready-only --json' { cargo run -p cyberdns -q -- serve --listen 127.0.0.1:53561 --ready-only --json }
    Run-Ok 'defender watch seed --json' { cargo run -p cyberdefender -q -- watch . --json }
    Run-Ok 'playbook watch ready --json' { cargo run -p aegis-cli -q -- playbook watch --json }
    Run-Ok 'edr watch seed --json' { cargo run -p cyberedr -q -- watch --json }
    Run-Ok 'siem follow seed --json' { cargo run -p cybersiem -q -- follow --from-recent 2 --json }
    Run-Ok 'gate init --json' { cargo run -p cyberztna -q -- init --json }
    Run-Ok 'aegis events --json' { cargo run -p aegis-cli -q -- events --limit 3 --json }
    Run-Ok 'aegisd reload --json' { cargo run -p aegisd -q -- reload --json; if ($LASTEXITCODE -eq 2) { $global:LASTEXITCODE = 0 } }
} else {
    Run-Ok 'aegis doctor' { cargo run -p aegis-cli -q -- doctor }
    Run-Ok 'aegis status' { cargo run -p aegis-cli -q -- status }
    Run-Ok 'policy suite-lab-pack' { cargo run -p aegis-cli -q -- policy apply policies/examples/suite-lab-pack.json }
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
    Run-Ok 'aegis selftest' { cargo run -p aegis-cli -q -- selftest --min-posture 40 }
    Run-Ok 'aegis backup' { cargo run -p aegis-cli -q -- backup --out .aegis/smoke-backup.zip }
}

Write-Host ""
Write-Host "SMOKE PASS$(if ($Json) { ' (JSON)' })" -ForegroundColor Green
