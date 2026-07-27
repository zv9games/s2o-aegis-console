# S2O Aegis — Operator runbook (T0)

## One front door

```powershell
cargo run -p aegis-cli -- version
cargo run -p aegis-cli -- doctor
cargo run -p aegis-cli -- status
cargo run -p aegis-cli -- report
cargo run -p aegis-cli -- report --json --out .aegis/report.json
cargo run -p aegis-cli -- policy apply policies/examples/edge-pack.json
cargo run -p aegis-cli -- events --limit 20
cargo run -p aegis-cli -- watch
cargo run -p aegis-cli -- rotate
cargo run -p aegis-cli -- playbook init
cargo run -p aegis-cli -- playbook run              # dry-run
cargo run -p aegis-cli -- playbook run --apply      # mutate blocklist etc.
```

### Daemon health endpoint

```powershell
cargo run -p aegisd -- start
# other terminal:
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/status
# disable: cargo run -p aegisd -- start --no-health
```

## First-time host setup

1. Link `net-lib` (Windows engines):

   ```powershell
   pwsh -File scripts/setup-net-lib.ps1
   ```

2. Build suite:

   ```powershell
   cargo build -p aegis-cli -p aegisd -p cyberwall-cli -p cyberdns `
     -p cyberdefender -p cyberedr -p cybersiem -p cyberintel -p cyberid `
     -p cybermesh -p cyberztna
   ```

3. Apply baseline policy + posture:

   ```powershell
   cargo run -p aegis-cli -- policy apply policies/examples/edge-pack.json
   cargo run -p cyberid -- posture --min-score 40
   ```

4. Optional install to `%LOCALAPPDATA%\S2O\Aegis\bin`:

   ```powershell
   pwsh -File scripts/install-aegis-tools.ps1 -Release
   pwsh -File scripts/install-aegis-tools.ps1 -Release -RegisterTask
   ```

## Product commands (deep CLIs)

| Job | Command |
|-----|---------|
| Firewall | `cyberwall status\|enable\|lock` |
| DNS | `cyberdns resolve\|block\|serve` |
| Defender | `cyberdefender scan\|update-defs` |
| EDR | `cyberedr processes\|ps\|alerts` |
| SIEM | `cybersiem stats\|correlate\|events` |
| Intel | `cyberintel sync\|lookup\|add` |
| Identity | `cyberid posture` |
| Mesh | `cybermesh genkey\|config\|show` |
| Gate | `cyberztna serve [--tls] --upstream URL` |

## Gate HTTPS (self-signed)

```powershell
cargo run -p cyberztna -- serve --tls --listen 127.0.0.1:18443 --upstream https://example.com
# certs: .aegis/gate-cert.pem , .aegis/gate-key.pem
# curl -k https://127.0.0.1:18443/
```

Posture score is cached ~15s; denied requests return HTTP 403 with `x-aegis-posture-score`.

## Event store

- Default path: `.aegis/events.jsonl`
- Auto-rotate at 10 MiB (keeps `.1` … `.5`)
- Force: `aegis rotate`

## Smoke

```powershell
pwsh -File scripts/dev-smoke.ps1
```

## Honesty

`aegis status` is ground truth. Demo labels require `AEGIS_DEMO=1`.  
Tier ceiling remains **T0** (userspace) until revenue justifies kernel/driver work.
