# S2O Aegis — Split2ops Cyber-Ops Platform

![Language](https://img.shields.io/badge/language-Rust%202021-orange)
![Phase](https://img.shields.io/badge/phase-2%20shell-yellow)
![Tier](https://img.shields.io/badge/tier%20ceiling-T0-blue)
![License](https://img.shields.io/badge/license-Commercial-red)

**S2O Aegis** is a modular Rust cyber-ops suite: **one suite kernel** (`aegisd` / `s2o-kernel`) and **nine product worlds**. Built for honest status, portable seams across major OS lines, and real host control before marketing claims.

> **Current maturity:** Phase 2 shell (foundation complete). Cyberwall is real on Windows. DNS has DoH + local blocklist. Other worlds are partial or not implemented. See `aegisd status` — it does not lie.

---

## Architecture

```text
  Operator CLI / optional egui console
              │
           aegisd          ← suite kernel (front door)
              │
     s2o-schema · s2o-store · s2o-bus · s2o-kernel
              │
   ┌──────────┼──────────┬──────────┬──── ... ────┐
 Cyberwall  CyberDNS  Defender   EDR    Log  Intel  ID  Mesh  Gate
```

| Layer | Role |
|-------|------|
| **Kernel** | Health matrix, policy apply, host id, event routing |
| **Schema / store / bus** | Shared data package (JSONL MVP; IPC later) |
| **Worlds** | Domain engines; OS backends behind traits |

**Tier ceiling today:** T0 (portable userspace). No kernel drivers / divert product until revenue justifies T2.

Docs: [docs/ROADMAP.md](docs/ROADMAP.md) · [docs/PHASE1.md](docs/PHASE1.md) · [docs/OS_MATRIX.md](docs/OS_MATRIX.md) · [docs/BUILD.md](docs/BUILD.md)

---

## Product matrix (honest)

| # | World | Binary | State (typical Windows) |
|---|--------|--------|-------------------------|
| 1 | Cyberwall | `cyberwall` | **implemented** — COM + netsh managed rules (`S2O-Aegis-*`) |
| 2 | CyberDNS | `cyberdns` | **partial** — DoH + allowlist/blocklist + IOC + UDP proxy |
| 3 | CyberDefender | `cyberdefender` | **partial** — hash/name + yara-lite + YARA-X lab rules + IOC |
| 4 | CyberEDR | `cyberedr` | **partial** — TCP + listen inventory + process/baseline + heuristics |
| 5 | CyberLog | `cybersiem` | **partial** — JSONL filter/stats + UDP syslog collect |
| 6 | ThreatGrid | `cyberintel` | **partial** — local IOC + capped multi-feed online sync |
| 7 | CyberID | `cyberid` | **partial** — weighted posture score + gate |
| 8 | CyberMesh | `cybermesh` | **partial** — X25519 keys + WG conf; optional system wg |
| 9 | Gate | `cyberztna` | **partial** — posture proxy + mTLS/JWT/OIDC + OAuth device/auth-code lab |
| — | Kernel | `aegisd` | **implemented** — status, policy, start |

`AEGIS_DEMO=1` can label stubs as demo — **never the default**.

---

## Quickstart

### 1. Link `net-lib` (Windows policy backend)

```powershell
pwsh -File scripts/setup-net-lib.ps1
# or: $env:S2O_NET_LIB = 'C:\ZV9\lines\s2o\net-lib'; pwsh -File scripts/setup-net-lib.ps1
```

Path deps expect a sibling `net-lib` next to the repo parent. See [docs/BUILD.md](docs/BUILD.md).

### 2. Build suite crates

```powershell
cargo check
cargo build -p aegisd -p cyberwall-cli -p cyberdns -p cybersiem
```

### 3. One front door (`aegis`)

```powershell
cargo run -p aegis-cli -- setup
cargo run -p aegis-cli -- config init
cargo run -p aegis-cli -- doctor
cargo run -p aegis-cli -- status
cargo run -p aegis-cli -- report --out .aegis/report.md
cargo run -p aegis-cli -- policy apply policies/examples/edge-pack.json
cargo run -p aegis-cli -- events --limit 20
# deep CLIs still available:
cargo run -p aegisd -- status --json
cargo run -p cyberwall-cli -- status
```

### 4. DNS / Defender / EDR

```powershell
cargo run -p cyberdns -- block evil.example
cargo run -p cyberdns -- resolve evil.example   # exit 3 if blocked
# local UDP proxy (blocklist + DoH). Default port 53553 (5353 often blocked on Windows)
cargo run -p cyberdns -- serve --listen 127.0.0.1:53553
# other terminal: nslookup -port=53553 example.com 127.0.0.1

cargo run -p cyberdefender -- update-defs
cargo run -p cyberdefender -- scan Cargo.toml
cargo run -p cyberdefender -- scan suspect.bin --quarantine
cargo run -p cyberedr -- processes --limit 16
cargo run -p cyberedr -- ps --limit 20
cargo run -p cyberedr -- baseline
cargo run -p cyberedr -- drift
cargo run -p cyberedr -- alerts
cargo run -p cyberintel -- sync
cargo run -p cyberintel -- lookup malware.test.s2o
cargo run -p cybersiem -- events

# Gate (ZTNA MVP) — posture-gated reverse proxy
cargo run -p cyberztna -- init
cargo run -p cyberztna -- check --min-score 50
cargo run -p cyberztna -- serve --upstream https://example.com --listen 127.0.0.1:18443
cargo run -p cyberztna -- serve --tls --upstream https://example.com --listen 127.0.0.1:18443
# access log: .aegis/gate-access.log

# Local sessions + Gate enforcement
cargo run -p cyberid -- authenticate alice --min-score 50
cargo run -p cyberztna -- serve --require-session --allow-ip 127.0.0.1 --rate-limit 120 --upstream https://example.com
# curl -H "X-Aegis-Session: <token>" http://127.0.0.1:18443/

# Mesh — keys + WireGuard conf (import with system WG / wg-quick)
cargo run -p cybermesh -- config --output .aegis/wg0.conf --address 10.220.0.2/32

# Event log rotation / backup / selftest
cargo run -p aegis-cli -- rotate
cargo run -p aegis-cli -- backup
cargo run -p aegis-cli -- selftest

# Full developer smoke
pwsh -File scripts/dev-smoke.ps1

# Install tools locally (+ optional logon task for aegisd)
pwsh -File scripts/install-aegis-tools.ps1 -Release
```

See [docs/OPERATOR.md](docs/OPERATOR.md) for the runbook.

---

## Workspace layout

```text
crates/
  s2o-schema · s2o-store · s2o-bus · s2o-kernel
  cyberwall-core · backend-{windows,linux,macos} · cyberwall-cli
  cyberdns · cyberdefender · cyberedr · cybersiem · cyberintel
  cyberid · cybermesh · cyberztna · aegisd
src/          # legacy egui / xallfirewall UI (frozen; not default build)
policies/     # example policy packs
docs/         # roadmap, OS matrix, build
scripts/      # setup-net-lib.ps1
```

---

## Multi-OS

| OS | Goal |
|----|------|
| Windows | Primary concrete (Cyberwall T0) |
| Linux | Build + partial nft/firewalld |
| macOS | Build + partial socketfilterfw |
| FreeBSD | Later |

Seams first, parity later. Status reports `unsupported_on_os` / `partial` honestly.

---

## Support

- **Developer:** Split2ops Software  
- **Remote:** [github.com/zv9games/s2o-aegis-console](https://github.com/zv9games/s2o-aegis-console)  
- **Contact:** `support@zv9games.org`

Copyright © 2026 Split2ops Software. All rights reserved.
