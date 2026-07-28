# S2O Aegis — Operator runbook (T0)

## One front door

```powershell
cargo run -p aegis-cli -- setup
cargo run -p aegis-cli -- setup --policy suite --enroll-fleet --json
cargo run -p aegis-cli -- setup --policy edge --no-policy
# Custom data root (also set AEGIS_DATA_DIR for posture/doctors that default to .aegis):
#   $env:AEGIS_DATA_DIR = "D:\aegis-data"
#   cargo run -p aegis-cli -- setup --data-dir D:\aegis-data --policy suite --enroll-fleet --json
# Windows service (requires Administrator):
#   cargo run -p aegis-cli -- service install --json
#   cargo run -p aegis-cli -- service start --json
cargo run -p aegis-cli -- version
cargo run -p aegis-cli -- doctor
cargo run -p aegis-cli -- status
cargo run -p aegis-cli -- report
cargo run -p aegis-cli -- report --json --out .aegis/report.json
cargo run -p aegis-cli -- policy validate policies/examples/edge-pack.json
cargo run -p aegis-cli -- policy plan policies/examples/edge-pack.json
cargo run -p aegis-cli -- policy apply policies/examples/edge-pack.json
cargo run -p aegis-cli -- policy plan policies/examples/suite-lab-pack.json --json
cargo run -p aegis-cli -- policy apply policies/examples/suite-lab-pack.json --json
cargo run -p aegis-cli -- policy apply policies/examples/suite-lab-pack.json --data-dir .aegis --json
cargo run -p aegis-cli -- policy apply policies/examples/mesh-seed-pack.json --json
# Custom data root (setup already rebases):
#   cargo run -p aegis-cli -- setup --data-dir D:\aegis-data --policy suite --json
#   cargo run -p aegis-cli -- policy apply policies/examples/suite-lab-pack.json --data-dir D:\aegis-data --event-log D:\aegis-data\events.jsonl --json
# Full JSON automation smoke (after cargo build):
#   pwsh -File scripts/dev-smoke.ps1 -Json
cargo run -p cyberdefender -- rules list
cargo run -p cyberdefender -- rules export --format csv --out .aegis/defender-rules.csv
cargo run -p aegis-cli -- cleanup                    # dry-run (+ IOC age + DNS dedupe)
cargo run -p aegis-cli -- cleanup --apply
cargo run -p cyberdns -- import domains.txt --list block
cargo run -p cyberdns -- import domains.txt --list allow --dry-run
cargo run -p aegis-cli -- config get min_posture
cargo run -p aegis-cli -- config set min_posture 50
cargo run -p cyberid -- sessions-export --format csv --out .aegis/sessions.csv
cargo run -p cyberdefender -- rules add-name lab-malware
cargo run -p cyberdefender -- rules add-hash deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
cargo run -p cyberdefender -- rules remove-name lab-malware
cargo run -p cyberedr -- ps --json --limit 10
cargo run -p cyberedr -- baseline-export --format csv --out .aegis/baseline.csv
cargo run -p cyberedr -- drift --json
cargo run -p cyberintel -- import-file .aegis/import-lab.txt --kind domain --dry-run
cargo run -p cyberintel -- import-file .aegis/import-lab.txt --source lab
# Managed Windows rules (prefix S2O-Aegis-*; elevate for live apply)
cargo run -p cyberwall -- apply policies/examples/wall-rules-engine.json --dry-run
cargo run -p cyberwall -- apply policies/examples/wall-rules-engine.json
cargo run -p cyberwall -- rules --managed --json
cargo run -p cyberdns -- export --list block --format csv --out .aegis/blocklist.csv
cargo run -p cyberdns -- dedupe --list block          # dry-run
cargo run -p cyberdns -- dedupe --list block --apply
cargo run -p aegis-cli -- policy apply policies/examples/wall-rules-lab.json
cargo run -p aegis-cli -- events --limit 20
cargo run -p aegis-cli -- events --since 1h --product dns --text
cargo run -p aegis-cli -- events --severity high --limit 10 --text
cargo run -p cyberwall -- doctor
cargo run -p cyberdefender -- doctor
cargo run -p cyberztna -- doctor
cargo run -p cyberztna -- status --json
cargo run -p cyberztna -- check --json
cargo run -p cyberztna -- routes --json
cargo run -p cyberztna -- route-add lab-api --path-prefix /api --upstream http://127.0.0.1:8080 --json
cargo run -p cyberztna -- route-remove lab-api --json
cargo run -p cyberztna -- access-export --since 24h --format csv --out .aegis/gate-access.csv
cargo run -p cyberedr -- listen --json --limit 20
cargo run -p cyberedr -- alerts --json
cargo run -p aegis-cli -- playbook run --path policies/examples/response-playbooks.json --json
cargo run -p cybermesh -- peers list --json
cargo run -p cybermesh -- peers show hub --json
cargo run -p cybermesh -- peers set hub --endpoint 10.0.0.1:51820
cargo run -p cybermesh -- peers export --format csv --out .aegis/mesh-peers.csv
cargo run -p cyberdns -- system-dns show --json
cargo run -p cyberedr -- processes --json --limit 20
cargo run -p cyberztna -- audit --json
cargo run -p cyberztna -- jwt mint labuser --secret lab-secret --json
cargo run -p cyberztna -- jwt verify <token> --secret lab-secret --json
cargo run -p aegis-cli -- fleet tag-add $env:COMPUTERNAME lab smoke
cargo run -p aegis-cli -- fleet tag-remove $env:COMPUTERNAME smoke
cargo run -p aegis-cli -- fleet doctor
cargo run -p aegis-cli -- doctor
cargo run -p aegis-cli -- doctor --json
cargo run -p aegis-cli -- health                 # probe aegisd /health
cargo run -p aegis-cli -- health --status --metrics
cargo run -p aegis-cli -- selftest
cargo run -p cybersiem -- doctor
cargo run -p cybersiem -- status --json
cargo run -p cybersiem -- events --limit 10 --json
cargo run -p cybersiem -- search "blocklist" --since 24h --max 20
cargo run -p cybersiem -- search gate --product cyberztna --json
cargo run -p cybersiem -- correlate evil.example --json
cargo run -p aegis-cli -- fleet export --format csv --out .aegis/fleet.csv
cargo run -p aegis-cli -- fleet status --json
cargo run -p aegis-cli -- playbook run --json
cargo run -p aegis-cli -- playbook show echo-dns-blocks
cargo run -p aegis-cli -- playbook show echo-dns-blocks --json
cargo run -p cyberintel -- doctor
cargo run -p cyberintel -- status --json
cargo run -p cyberintel -- list --limit 20 --json
cargo run -p cyberintel -- lookup evil.example --json
cargo run -p cyberintel -- remove playbook-ioc-smoke.s2o          # dry-run
cargo run -p cyberintel -- remove playbook-ioc-smoke.s2o --apply
cargo run -p cyberid -- status --json
cargo run -p cyberid -- doctor --json
cargo run -p cybermesh -- status --json
cargo run -p cybermesh -- doctor --json
cargo run -p cyberid -- sessions --json
cargo run -p cyberid -- sessions --all --user operator
cargo run -p cyberid -- revoke --user labuser --json
cargo run -p cyberid -- gc --json
cargo run -p cyberedr -- status --json
cargo run -p cyberedr -- baseline --json
cargo run -p cyberedr -- export --state established --format csv --out .aegis/tcp.csv
cargo run -p cyberedr -- export --state listen --limit 50
cargo run -p cyberdefender -- status --json
cargo run -p cyberdefender -- scan .aegis --json --max-files 20
cargo run -p cyberdefender -- patterns test --text "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" --json
cargo run -p cyberdefender -- yara test --text "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" --json
cargo run -p cyberdefender -- quarantine list --json
cargo run -p aegis-cli -- emit "ops smoke" --json
cargo run -p aegis-cli -- selftest --json
cargo run -p aegis-cli -- cleanup --json
cargo run -p cyberwall -- apply policies/examples/wall-rules-engine.json --dry-run --json
cargo run -p aegis-cli -- watch
# emit locally and/or to aegisd bus
cargo run -p aegis-cli -- emit "lab alert" --severity high --product wall
cargo run -p aegis-cli -- emit "remote" --http http://127.0.0.1:9090/events --no-local
cargo run -p aegis-cli -- emit "udp" --udp 127.0.0.1:9091 --no-local
cargo run -p aegis-cli -- rotate
cargo run -p aegis-cli -- playbook init
cargo run -p aegis-cli -- playbook list
cargo run -p aegis-cli -- playbook show echo-dns-blocks --json
cargo run -p aegis-cli -- playbook validate
cargo run -p aegis-cli -- playbook disable webhook-on-high-block
cargo run -p aegis-cli -- playbook enable emit-on-high-block
cargo run -p aegis-cli -- playbook remove disposable-rule          # dry-run
cargo run -p aegis-cli -- playbook remove disposable-rule --apply
cargo run -p aegis-cli -- playbook run              # dry-run (log/dns/emit/ioc_add_attr/…)
cargo run -p aegis-cli -- playbook run --apply      # mutate blocklist / IOC store etc.
cargo run -p cybersiem -- stats --since 24h --json
cargo run -p cybersiem -- top --attr domain --n 5 --json
cargo run -p aegis-cli -- policy plan policies/examples/dns-intel-pack.json
cargo run -p aegis-cli -- policy apply policies/examples/dns-intel-pack.json
cargo run -p cyberdns -- status --json
cargo run -p cyberdns -- list --json --limit 50
cargo run -p cyberdns -- list --allow --json
cargo run -p cyberdns -- block evil.lab.s2o --json
cargo run -p cyberdns -- allow updates.example.com --json
cargo run -p cyberdns -- dedupe --json
cargo run -p cyberdns -- import domains.txt --dry-run --json
cargo run -p cyberdns -- resolve example.com --json
cargo run -p cyberdns -- doctor
cargo run -p cyberdns -- doctor --probe-doh
cargo run -p cyberdns -- check evil.example --json
cargo run -p cyberid -- authenticate labuser --json
cargo run -p cyberid -- verify <token> --json
cargo run -p cyberdefender -- patterns list --json
cargo run -p cyberdefender -- yara list --json
cargo run -p cyberdefender -- rules add-name lab-marker --json
cargo run -p cyberedr -- doctor
cargo run -p aegis-cli -- version --json
cargo run -p aegis-cli -- setup --no-policy --json
cargo run -p aegis-cli -- selftest
cargo run -p aegis-cli -- config show --json
cargo run -p aegis-cli -- config get min_posture --json
cargo run -p aegis-cli -- config set min_posture 40 --json
cargo run -p aegis-cli -- config init --json
cargo run -p aegis-cli -- playbook enable emit-on-high-block --json
cargo run -p aegis-cli -- playbook disable emit-on-high-block --json
cargo run -p cyberdefender -- quarantine purge --json
cargo run -p cyberintel -- import-file iocs.txt --dry-run --json
cargo run -p cyberintel -- sync --json
cargo run -p cyberwall -- enable --json
cargo run -p cyberdns -- system-dns backup --json
cargo run -p aegis-cli -- fleet policy set policies/examples/posture-pack.json --json
cargo run -p aegis-cli -- fleet policy show --json
cargo run -p aegis-cli -- fleet policy apply --json
cargo run -p aegis-cli -- fleet sync --dry-run --json
cargo run -p aegis-cli -- fleet sync --json
# With aegisd up: agent re-applies when desired policy is newer
#   cargo run -p aegisd -- start --health-bind 127.0.0.1:9090
#   cargo run -p aegis-cli -- fleet heartbeat --push http://127.0.0.1:9090/fleet/heartbeat --json
#   cargo run -p aegis-cli -- fleet sync --base-url http://127.0.0.1:9090 --json
cargo run -p aegis-cli -- service status --json
# Release stage (Windows):
#   pwsh -File scripts/release-package.ps1
cargo run -p aegis-cli -- service stop --json
cargo run -p aegis-cli -- policy example --kind edge --json
cargo run -p aegis-cli -- playbook init --json
cargo run -p cyberdefender -- update-defs --json
cargo run -p cyberdefender -- patterns init --json
cargo run -p cyberdefender -- yara init --json
cargo run -p cyberdefender -- yara scan Cargo.toml --json
cargo run -p cybermesh -- show --json
cargo run -p cybermesh -- up --json
cargo run -p cybermesh -- peers set lab-peer --keepalive 30 --json
cargo run -p cyberztna -- init --json
cargo run -p cyberztna -- mtls init --json
cargo run -p cyberztna -- jwt keygen --json
cargo run -p cyberztna -- oauth code --url-only --json
cargo run -p aegisd -- policy example --kind edge --json
cargo run -p aegisd -- policy apply policies/examples/posture-pack.json --json
cargo run -p aegisd -- reload --json
cargo run -p aegis-cli -- events --json
cargo run -p aegis-cli -- watch --from-recent 3 --json
cargo run -p cybersiem -- collect --stdin-once --json
cargo run -p cybersiem -- follow --from-recent 3 --json
cargo run -p cyberedr -- trace --json
cargo run -p cyberedr -- watch --json
cargo run -p cyberedr -- net-watch --json
cargo run -p cyberdefender -- realtime status --json
cargo run -p cyberdefender -- watch . --json
cargo run -p cyberdns -- serve --ready-only --json
cargo run -p cyberdns -- serve --max-queries 1 --json
cargo run -p aegis-cli -- playbook watch --json
cargo run -p aegis-cli -- policy apply policies/examples/dns-intel-pack.json --json
cargo run -p aegis-cli -- policy plan policies/examples/posture-pack.json --json
cargo run -p aegis-cli -- policy plan policies/examples/mesh-seed-pack.json --json
cargo run -p aegis-cli -- fleet enroll --json
cargo run -p aegis-cli -- fleet heartbeat --json
cargo run -p aegis-cli -- fleet prune --json
cargo run -p aegis-cli -- backup --json
cargo run -p aegis-cli -- rotate --json
cargo run -p cyberztna -- mtls status --json
cargo run -p cyberztna -- connect demo --json
cargo run -p cybermesh -- genkey --json
cargo run -p cybermesh -- config --private-key-file .aegis/wg-private.key --json
cargo run -p cyberintel -- add domain ioc-lab.s2o --json
cargo run -p cyberintel -- remove ioc-lab.s2o --json
cargo run -p aegis-cli -- cleanup              # dry-run sessions/fleet/events hygiene
cargo run -p aegis-cli -- cleanup --apply
cargo run -p cyberintel -- export --format csv --out .aegis/ioc.csv --limit 1000
cargo run -p cyberintel -- stats
cargo run -p cyberintel -- stats --json
cargo run -p cyberintel -- prune --older-days 90 --source openphish --json   # dry-run
cargo run -p cyberintel -- prune --older-days 90 --apply --json
cargo run -p cyberztna -- access-stats --since 24h
cargo run -p cyberztna -- access-stats --since 1h --json
cargo run -p aegis-cli -- backup
cargo run -p aegis-cli -- restore .aegis-backup-XXXX.zip --force
# mesh endpoint TCP probe (userspace; not WG handshake)
cargo run -p cybermesh -- probe
cargo run -p cybermesh -- probe --endpoint 1.1.1.1:443 --json
```

### Syslog export

```powershell
# print RFC5424-ish lines
cargo run -p cybersiem -- export --format syslog --limit 20
# time window (relative or RFC3339)
cargo run -p cybersiem -- events --since 1h --limit 50
cargo run -p cybersiem -- alerts --since 24h
cargo run -p cybersiem -- stats --since 15m
cargo run -p cybersiem -- top --since 7d --attr domain
# send UDP (listener must accept)
cargo run -p cybersiem -- export --format syslog --syslog-udp 127.0.0.1:5514 --limit 20
# live collect (UDP syslog → JSONL)
cargo run -p cybersiem -- collect --listen 127.0.0.1:5514 --max-events 10
# lab inject without network:
echo "<14>lab test message" | cargo run -p cybersiem -- collect --stdin-once
# multi-feed IOC sync (capped)
cargo run -p cyberintel -- sync --online --max-import 200
```

### Daemon health endpoint

```powershell
cargo run -p aegisd -- start
# other terminal:
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/status
curl http://127.0.0.1:9090/metrics
# disable: cargo run -p aegisd -- start --no-health
```

### Config + continuous playbooks

```powershell
cargo run -p aegis-cli -- config init
cargo run -p aegis-cli -- config show
cargo run -p aegis-cli -- playbook watch          # dry-run on new events
cargo run -p aegis-cli -- playbook watch --apply  # live responses
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
   # Real Windows Service (Administrator):
   pwsh -File scripts/install-aegis-tools.ps1 -Release -RegisterService
   cargo run -p aegis-cli -- service install
   cargo run -p aegis-cli -- service start
   cargo run -p aegis-cli -- service status
   ```

## Product commands (deep CLIs)

| Job | Command |
|-----|---------|
| Firewall | `cyberwall status\|doctor\|enable\|lock\|rules [--managed]\|apply` |
| DNS | `cyberdns doctor\|check\|export\|import\|dedupe\|resolve\|block\|allow\|serve\|system-dns` |
| Defender | `cyberdefender doctor\|rules list\|add-name\|add-hash\|scan\|yara\|quarantine` |
| EDR | `cyberedr doctor\|export\|ps --json\|baseline\|baseline-export\|drift --json\|listen --json\|alerts --json\|net-watch` |
| Service | `aegis service install\|start\|stop\|status` (Windows) |
| Linux | `scripts/s2o-aegisd.service` (systemd) |
| Events | `aegis emit\|events\|watch` ; aegisd `GET/POST /events` + `--event-udp` |
| SIEM | `cybersiem doctor\|search\|stats --json\|top --json\|alerts\|correlate\|collect\|follow` |
| Mesh | `cybermesh doctor\|probe\|peers list\|export\|config\|genkey` |
| Intel | `cyberintel doctor\|import-file\|sync\|prune\|remove\|export\|stats\|lookup\|add` |
| Identity | `cyberid posture\|doctor\|authenticate\|sessions\|sessions-export\|revoke\|verify` |
| Gate | `cyberztna doctor\|serve\|routes\|route-add\|route-remove\|access-stats\|access-export\|oauth\|jwt` |

## Gate HTTPS + session

```powershell
cargo run -p cyberid -- authenticate alice --min-score 40
# copy Token...

cargo run -p cyberztna -- serve --tls --require-session `
  --listen 127.0.0.1:18443 --upstream https://example.com `
  --allow-ip 127.0.0.1 --allow-ip 10.0.0.0/8 `
  --rate-limit 120 --enforce-session-posture
# certs: .aegis/gate-cert.pem , .aegis/gate-key.pem

curl -k -H "X-Aegis-Session: aegis_..." https://127.0.0.1:18443/
# or: Authorization: Bearer aegis_...
```

Posture score is cached ~15s. Without a valid session (when `--require-session`), Gate returns **401**. Low posture returns **403** with `x-aegis-posture-score`. IP not on allowlist → **403**. Rate limit → **429**. Successful session use updates `last_used` (`cyberid sessions`). Cleanup: `cyberid gc`.

### mTLS + JWT (OIDC-lite)

```powershell
# Lab PKI
cargo run -p cyberztna -- mtls init --dir .aegis/mtls --force

# mTLS serve (client must present client.pem)
cargo run -p cyberztna -- serve --mtls-ca .aegis/mtls/ca.pem `
  --listen 127.0.0.1:18443 --upstream https://example.com --min-score 40

# Probe with lab client cert (rustls; Windows curl/schannel often cannot load PEM)
cargo run -p cyberztna -- mtls probe --url https://127.0.0.1:18443/ --also-plain

# Local JWT (not full OIDC discovery)
cargo run -p cyberztna -- jwt mint alice --secret lab-secret --posture 80
cargo run -p cyberztna -- serve --jwt-secret lab-secret --upstream https://example.com --min-score 40
# Authorization: Bearer <jwt>
```

Policy pack: `aegis policy apply policies/examples/gate-pack.json` writes gate defaults into `.aegis/gate-routes.json`.

## YARA-lite + YARA-X

```powershell
# yara-lite (substr / re: / hex:)
cargo run -p cyberdefender -- patterns init --force
cargo run -p cyberdefender -- patterns list
cargo run -p cyberdefender -- patterns test --text "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

# YARA-X (real .yar rules via pure-Rust yara-x)
cargo run -p cyberdefender -- yara init --force
cargo run -p cyberdefender -- yara list
cargo run -p cyberdefender -- yara test --text "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
cargo run -p cyberdefender -- yara scan .aegis --recursive --max-files 64
cargo run -p cyberdefender -- scan .aegis --recursive --yara --max-files 64
cargo run -p cyberdefender -- scan path\to\file --yara-only
cargo run -p cyberdefender -- watch .aegis --interval-ms 3000 --yara
```

YARA-lite rule lines: `name: needle`, `name: re:regex`, `name: hex:90 90`, optional `[high] name: ...`.  
YARA-X rules: place `*.yar` / `*.yara` under `.aegis/yara` (seed via `yara init`). Not a cloud signature feed.

## Linux systemd

```bash
sudo install -m 755 target/release/aegisd /usr/local/bin/aegisd
sudo install -d /var/lib/s2o-aegis
sudo install -m 644 scripts/s2o-aegisd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now s2o-aegisd
curl -s http://127.0.0.1:9090/health
```

## Fleet inventory (local roster)

```powershell
cargo run -p aegis-cli -- fleet enroll --tag lab
cargo run -p aegis-cli -- fleet prune --stale-minutes 10080          # dry-run
cargo run -p aegis-cli -- fleet prune --stale-minutes 10080 --apply  # drop stale
cargo run -p aegis-cli -- fleet heartbeat
cargo run -p aegis-cli -- fleet list
cargo run -p aegis-cli -- fleet status

# With aegisd health HTTP:
cargo run -p aegisd -- start --health-bind 127.0.0.1:9090
# GET  http://127.0.0.1:9090/fleet
# GET  http://127.0.0.1:9090/fleet/summary
# POST http://127.0.0.1:9090/fleet/heartbeat  (JSON HeartbeatPayload)
cargo run -p aegis-cli -- fleet heartbeat --push http://127.0.0.1:9090/fleet/heartbeat
```

Store: `.aegis/fleet.json` (file-backed; not a multi-tenant control plane yet).

### Fleet policy distribution

```powershell
# Hub: publish desired pack
cargo run -p aegis-cli -- fleet policy set policies/examples/gate-pack.json
cargo run -p aegis-cli -- fleet policy show
cargo run -p aegisd -- start --health-bind 127.0.0.1:9090
cargo run -p aegis-cli -- fleet policy push policies/examples/gate-pack.json --url http://127.0.0.1:9090/fleet/policy

# Agent: pull + apply
cargo run -p aegis-cli -- fleet policy pull --url http://127.0.0.1:9090/fleet/policy --apply
cargo run -p aegis-cli -- fleet sync --base-url http://127.0.0.1:9090 --json
cargo run -p aegis-cli -- fleet heartbeat --push http://127.0.0.1:9090/fleet/heartbeat
# response includes desired_policy_version + policy_stale
```

### Gate JWT RS256 / JWKS

```powershell
cargo run -p cyberztna -- jwt keygen --dir .aegis/jwt --force
cargo run -p cyberztna -- jwt mint alice --rsa-key .aegis/jwt/jwt-private.pem --posture 80
cargo run -p cyberztna -- jwt verify <token> --jwks .aegis/jwt/jwks.json
cargo run -p cyberztna -- serve --jwt-jwks .aegis/jwt/jwks.json --upstream https://example.com --min-score 40
# Remote JWKS at start (caches to file):
cargo run -p cyberztna -- serve --jwt-jwks-url http://127.0.0.1:9090/jwks.json --upstream https://example.com
cargo run -p cyberztna -- jwt fetch-jwks --url https://example.com/.well-known/jwks.json

# OIDC discovery (fetch openid-configuration + jwks_uri, validate iss):
cargo run -p cyberztna -- jwt keygen --dir .aegis/jwt --force
cargo run -p aegisd -- start --health-bind 127.0.0.1:9090 --jwks .aegis/jwt/jwks.json
cargo run -p cyberztna -- jwt oidc-discover http://127.0.0.1:9090 --fetch-jwks
cargo run -p cyberztna -- jwt mint alice --rsa-key .aegis/jwt/jwt-private.pem --issuer http://127.0.0.1:9090
cargo run -p cyberztna -- serve --oidc-issuer http://127.0.0.1:9090 --upstream https://example.com --min-score 40

# OAuth device-code (RFC 8628 lab):
# terminal A: cyberztna oauth device --issuer http://127.0.0.1:9090
# terminal B: cyberztna oauth approve ABCD-EFGH --user alice --issuer http://127.0.0.1:9090
# OAuth authorization-code (lab; auto-approve OOB):
# cyberztna oauth code --issuer http://127.0.0.1:9090
# cyberztna oauth code --url-only   # print authorize URL only
# cyberztna oauth code --code ac_...  # exchange existing code
# (or open verification_uri in a browser)
# Use access_token as: Authorization: Bearer …
```

### Mesh multi-peer

```powershell
cargo run -p cybermesh -- genkey --write-private .aegis/wg0.key --write-public .aegis/wg0.pub
cargo run -p cybermesh -- peers add hub <BASE64_PUB> --endpoint hub.example:51820
cargo run -p cybermesh -- peers list
cargo run -p cybermesh -- config --private-key-file .aegis/wg0.key --address 10.220.0.2/32
# Peer directory via aegisd:
cargo run -p cybermesh -- peers publish .aegis/wg0.pub --endpoint 1.2.3.4:51820
cargo run -p cybermesh -- peers pull --merge
```

### System DNS bind (hijack-lite)

```powershell
# Show current OS DNS, then point at loopback (Admin shell on Windows)
cargo run -p cyberdns -- system-dns show
cargo run -p cyberdns -- system-dns backup
cargo run -p cyberdns -- system-dns set --server 127.0.0.1
# restore previous:
cargo run -p cyberdns -- system-dns restore
# Pair with: cyberdns serve --listen 127.0.0.1:53   (or 53553 + port proxy)
```

### EDR rich process intel

```powershell
cargo run -p cyberedr -- ps --rich --limit 20
cargo run -p cyberedr -- watch --rich --interval-ms 2000 --max-events 5
```

### Console API (aegisd)

```text
GET  /api/v1/health | /status | /posture | /events?limit=20 | /fleet | /metrics
GET/POST /api/v1/mesh/peers
GET/POST /api/v1/fleet/policy
```

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
