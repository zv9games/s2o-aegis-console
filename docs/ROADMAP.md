# S2O Aegis — Roadmap (phases × tiers)

**Suite shape:** nine product worlds + **one suite kernel** (front door).  
**Portability:** major OS lines via backend traits — seams first, parity later.  
**Honesty:** status never lies. Demo mode is opt-in only (`AEGIS_DEMO=1`).

---

## Two axes (do not nest wrong)

| Axis | Question | Changes when |
|------|----------|--------------|
| **Phase** | What stage of the *house* ships? | Milestone / calendar |
| **Tier** | How deep / expensive may materials be? | Cost, risk, revenue, OS capability |

**Phases** are the construction sequence.  
**Tiers** are a **ceiling** on what a phase may use — not a mini T0→T1→T2 ladder inside every phase for every world.

```text
        T2  kernel/driver ────────── ceiling raised late / paid only
        T1  hardened host ────────── when services/agents need it
        T0  userspace ══════════════ default ceiling (always available)

P0 mark → P1 foundation → P2 shell → P3 roof → P4 systems → P5 interior
 (T0)        (T0)           (T0–T1)    (T0–T1)    (T1)         (T1–T2 opt)
```

### Avoid (tiers-per-phase nested ladders)

```text
Phase 1: wall T0→T1→T2, dns T0→T1→T2, … × 9
```

That is nine separate skyscrapers. You never get one portable suite.

### Do (phase with a tier ceiling)

```text
Phase 1: kernel + 9 contracts + multi-OS seams; Wall T0-deep;
         other worlds formed stubs; Windows concrete first.
```

---

## Construction map

| Stage | Phase | Meaning |
|-------|-------|---------|
| Mark the property | **P0** | Lot lines: schema, store, bus, product IDs, honesty |
| Scaffolding + concrete | **P1** | One kernel, nine room footprints, first pour (Wall T0) |
| Shell / framing | **P2** | Engines do real host work; events flow |
| Roof | **P3** | One weathertight product: CLI, install, policy pack |
| Wiring & plumbing | **P4** | IPC, Log, Intel, posture, cross-world playbooks |
| Interior | **P5** | Mesh, Gate, console, fleet; optional T2 |

**Big 9 at P1** = marked load-bearing slots in the registry — not nine finished products.

---

## Suite kernel (not a `.sys`)

The **1 kernel** is the Aegis control plane:

- lifecycle / health matrix  
- policy distribution  
- event spine (`s2o-schema` / `store` / `bus`)  
- host identity  
- operator entry (`aegisd` / later `aegis` CLI)

Worlds own OS enforcement. Kernel owns truth and contracts.

---

## Capability tiers

| Tier | Name | Allowed | Forbidden until ceiling raised |
|------|------|---------|--------------------------------|
| **T0** | Portable userspace | OS policy APIs, CLIs, DoH client, JSON/SQLite, orchestrate WireGuard tools | Custom drivers, divert-as-product |
| **T1** | Hardened host | Services, ETW/auditd/EndpointSecurity where APIs allow, signed user bins, installers | Custom kernel product core |
| **T2** | Kernel / advanced net | Signed callouts, WinDivert product path, advanced eBPF ship | — |

---

## Nine worlds (jobs)

| # | World | Job | Long-term tier appetite |
|---|--------|-----|-------------------------|
| 1 | Cyberwall | Host network policy | T0 core; T2 optional later |
| 2 | CyberDNS | Name-resolution security | T0 |
| 3 | CyberDefender | File / malware shield | T0–T1 |
| 4 | CyberEDR | Detect + respond | T1 (T2 optional) |
| 5 | CyberLog | Telemetry plane | T0–T1 |
| 6 | ThreatGrid | IOC / reputation context | T0 |
| 7 | CyberID | Identity + posture | T0–T1 |
| 8 | CyberMesh | Private overlay (orchestrate WG) | T0 |
| 9 | Gate | Zero-trust app access | T0–T1 |

---

## Phase overview

### P0 — Mark the property *(mostly done)*

Schema, JSONL store, in-process bus, honest `aegisd`, Windows Cyberwall via `s2o_net_lib`.

**Exit:** contracts exist; status can tell the truth.

### P1 — Scaffolding + concrete ✅ *landed*

See [PHASE1.md](./PHASE1.md) and [OS_MATRIX.md](./OS_MATRIX.md).

- One kernel surface (registry, health, policy v0, OS detect)  
- Nine world contracts / health slots  
- Multi-OS backend pattern  
- Cyberwall T0 pour (Windows deep; Linux start; macOS honest partial)  
- Build topology fixed (`net-lib` / adapters resolve)

**Tier ceiling:** T0 only.

### P2 — Shell ← *in progress*

- ✅ Cyberwall actions emit `AegisEvent` (CLI + policy apply)  
- ✅ CyberDNS DoH + persistent file blocklist + events  
- ✅ DNS policy fragment in kernel (`dns.block_domains`)  
- ✅ Defender hash scan + Defender service probe + events  
- ✅ EDR TCP snapshot + summary events  
- ✅ `aegis` meta-CLI (`doctor` / `status` / `policy` / `events`)  
- ✅ GitHub Actions CI (portable Ubuntu + optional Windows+net-lib)  
- ✅ CyberDNS local UDP proxy (`serve`, blocklist NXDOMAIN + DoH A)  
- ✅ CyberDefender local hash/name rules (`update-defs` + scan verdicts)  
- ✅ ThreatGrid local IOC store (`s2o-ioc`) + lookup/add/sync  
- ✅ DNS + Defender consume ThreatGrid IOCs  
- ✅ CyberEDR process inventory + heuristic alerts  
- ✅ yara-lite content patterns  
- ✅ YARA-X engine (`yara-x` crate) + lab seed rules + CLI
- ✅ CyberID posture score + events + min_score gate  
- ✅ CyberLog stats / filter / correlate  
- ✅ Policy intel sync + posture gate fragments  
- ✅ CyberMesh real X25519 WireGuard keygen  
- ✅ Gate MVP: posture-gated HTTP reverse proxy (`cyberztna serve`)  
- ✅ CyberMesh conf writer + optional `wg show` / `wg-quick` hooks  
- ✅ Event store size-based rotation (`aegis rotate`)  
- ✅ `scripts/dev-smoke.ps1` suite smoke  
- ✅ Gate HTTPS self-signed (`cyberztna serve --tls`)  
- ✅ Operator install script + OPERATOR.md + CHANGELOG  
- ✅ `aegis report` audit (markdown/JSON)  
- ✅ `aegisd` local health HTTP (`/health`, `/status`)  
- ✅ ThreatGrid `--online` feed sync (capped)  
- ✅ Live event watch (`aegis watch` / `cybersiem follow`)  
- ✅ Defender quarantine on block  
- ✅ Playbooks dry-run/apply (`aegis playbook`)  
- ✅ `aegis backup` / `restore` for data dir  
- ✅ CyberLog syslog export (+ optional UDP)  
- ✅ `aegis selftest`  
- ✅ `aegis setup` first-time bootstrap  
- ✅ EDR process baseline + drift  
- ✅ Playbook webhook action  
- ✅ Suite config.json + `aegis config`  
- ✅ Prometheus text `/metrics` on aegisd  
- ✅ Continuous `aegis playbook watch`  
- ✅ Gate access log file  
- ✅ CyberID local sessions (mint/list/revoke/verify)  
- ✅ Gate `--require-session` (CyberID token header)  
- ✅ Gate IP allowlist + rate limit + session posture floor + last_used  
- ✅ Windows Service SCM for aegisd + `aegis service`  
- ✅ CyberEDR `watch` (process poll / ETW-lite)  
- ✅ YARA-lite v1 (substr/re/hex + severity) + Defender watch/recursive  
- ✅ Linux systemd unit for aegisd  
- ✅ Gate mTLS (client CA) + JWT HS256 OIDC-lite + gate policy fragment  
- ✅ Fleet inventory MVP (`aegis fleet` + aegisd `/fleet`)  
- ✅ Fleet policy push/pull/apply + Gate RS256/JWKS file JWT  
- ✅ Gate remote JWKS URL + mesh multi-peer registry + `/api/v1` console surface  
- ✅ OIDC well-known discovery + lab IdP stub on aegisd  
- ✅ CyberDNS system-dns bind + EDR rich process intel (cmdline/ppid)  
- ✅ OAuth device-code lab flow (RFC 8628) on aegisd + Gate client  
- ✅ YARA-X engine in CyberDefender  
- ✅ Windows Cyberwall declarative `apply_policy` (managed `S2O-Aegis-*` netsh rules)  
- ✅ OAuth authorization-code lab grant (aegisd + Gate client; not prod IdP UI)  
- ✅ CyberLog UDP syslog collect + ThreatGrid multi-feed online sync (capped)  
- ✅ Multi-process event ingest (`POST /events`, UDP bus, `aegis emit`)  
- ✅ CyberDNS allowlist + EDR listen inventory  
- ✅ Linux managed firewall apply + mesh doctor + playbook emit/dns_allow  
- ✅ Defender quarantine list/restore/purge + macOS app-block apply_policy  
- ✅ DNS proxy stats + YARA pull + expanded selftest  
- ✅ Ingest metrics + fleet prune + CyberID doctor  
- ✅ DoH multi-resolver fallback + Gate access-stats  
- ✅ CyberLog alerts/top + EDR net-watch  
- ✅ IOC prune/export + aegis cleanup housekeeping  
- ✅ CyberLog `--since` window + mesh TCP probe + expanded report inventory  
- ✅ Playbook IOC actions + kind/attr matching + intel stats + Gate access-stats `--since`  
- ✅ DNS doctor/check + EDR doctor + playbook list/validate  
- ✅ Wall/Defender doctors + filtered `aegis events`  
- ✅ Gate doctor + fleet doctor + deeper suite doctor  
- ✅ ThreatGrid doctor/remove + CyberLog doctor + `aegis health` probe  
- ✅ Policy validate + DNS export/dedupe + wall rules managed filter  
- ✅ Session revoke (CLI + playbook) + EDR TCP export  
- ✅ Gate access-export + mesh peers export + expanded selftest  
- ✅ CyberLog search + fleet export + playbook run --json  
- ✅ Policy plan + defender rules export + expanded cleanup  
- ⏳ Kernel ETW / boringtun / prod browser IdP / commercial YARA feed (later)  
- Selective T1 if needed for telemetry APIs

### P3 — Roof

Unified `aegis` operator CLI, packaging/services, policy packs, release discipline across supported OS.

### P4 — Wiring & plumbing

Multi-process IPC, CyberLog pipeline, ThreatGrid lookup, posture, playbooks.

### P5 — Interior

Mesh + Gate, console as a *view* on the kernel API, fleet; T2 only with revenue/sponsor.

---

## Priority order (value path)

1. Topology / build green  
2. Kernel registry + honesty matrix  
3. Cyberwall depth + policy v0  
4. Events from wall → store  
5. DNS blocklist  
6. Posture (CyberID signals)  
7. EDR userspace  
8. ThreatGrid local IOC  
9. Mesh orchestrate + Gate MVP  
10. Fleet  
11. T2 differentiators  

---

## Mental model

> **Phases** build the house in order.  
> **Tiers** limit how exotic the materials can be.  
> **Nine worlds** are rooms on one foundation — not nine houses each with their own tier ladder.
