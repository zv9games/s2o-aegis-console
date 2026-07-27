# Changelog

## Unreleased / main

### 2026-07-27 — Phase 1 foundation through Gate + ops roof

#### Phase 1 — Foundation
- `s2o-schema`: HealthState, OsFamily, CapabilityTier, PolicyDocument
- `s2o-kernel`: registry, status matrix, policy apply, multi-OS firewall factory
- Cyberwall backends: Windows (COM), Linux (partial safe), macOS (partial)
- Docs: ROADMAP, OS_MATRIX, PHASE1, BUILD
- Honest README rewrite

#### Phase 2 — Shell
- CyberDNS: DoH, file blocklist, UDP proxy, ThreatGrid IOC deny
- CyberDefender: hash/name rules, yara-lite patterns, IOC hashes
- CyberEDR: TCP table, process inventory, heuristic alerts
- CyberLog: filter, stats, correlate
- ThreatGrid (`s2o-ioc`): local IOC store, lookup/add/sync
- CyberID: weighted posture score + min_score gate
- Policy: firewall + DNS + intel sync + posture fragments
- `aegis` meta-CLI: doctor, status, policy, events, rotate, version

#### Phase 3 start — Access
- CyberMesh: real X25519 keys, WG conf writer, optional wg/wg-quick
- Gate (`cyberztna`): posture-gated reverse proxy, routes file, audit
- Gate HTTPS: self-signed TLS via `--tls`

#### Ops
- Event store size rotation
- `scripts/setup-net-lib.ps1`, `dev-smoke.ps1`, `install-aegis-tools.ps1`
- GitHub Actions CI (portable Ubuntu + optional Windows net-lib)
- `docs/OPERATOR.md`
- `aegis report` markdown/JSON audit
- `aegisd start` health HTTP on `127.0.0.1:9090` (`/health`, `/status`)
- ThreatGrid `sync --online` (URLHaus text feed, capped)
- `aegis watch` / `cybersiem follow` live event tail
- Defender `--quarantine` for blocked files
- `aegis playbook init|run` dry-run/apply response rules
- `aegis backup` / `restore`, `aegis selftest`
- CyberLog syslog export with optional UDP ship
- `aegis setup` bootstrap for .aegis data + starter configs
- CyberEDR process baseline/drift
- Playbook `webhook` action (POST JSON)

### Known gaps (intentionally later)
- Full YARA-X engine, ETW/eBPF hooks
- System DNS hijack, embedded boringtun
- Gate mTLS / OIDC IdP
- Full Windows Service SCM integration (Scheduled Task provided)
