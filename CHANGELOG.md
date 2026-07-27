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
- Suite `.aegis/config.json` + `aegis config init|show`
- aegisd Prometheus `/metrics`
- Continuous `aegis playbook watch`
- Gate access log (`.aegis/gate-access.log`)
- CyberID local session tokens after posture gate
- Shared `s2o-session` crate; Gate `--require-session` (X-Aegis-Session / Bearer)
- Gate IP allowlist (`--allow-ip` / CIDR), per-IP rate limit (`--rate-limit`)
- Gate `--enforce-session-posture` (mint-time score vs min_score)
- Session `last_used` touch on Gate use; `cyberid gc` for store cleanup
- Windows Service SCM for aegisd (`--run-as-service`, `aegis service install|start|stop|status`)
- `scripts/install-aegis-service.ps1`; install tools `-RegisterService`
- CyberEDR `watch` process appearance poll (ETW-lite userspace)
- YARA-lite v1: `substr` / `re:` / `hex:` / severity tags; `patterns list|init|test`
- Defender `scan --recursive`, directory `watch` poll
- Linux systemd unit `scripts/s2o-aegisd.service`
- Gate mTLS: lab PKI (`cyberztna mtls init`) + `--mtls-ca` client cert required
- Gate JWT HS256 OIDC-lite (`--jwt-secret`, `cyberztna jwt mint|verify`)
- Policy `gate` fragment + `policies/examples/gate-pack.json`
- Fleet inventory MVP: `s2o-fleet`, `aegis fleet enroll|heartbeat|list|show|remove|status`
- aegisd HTTP: `GET /fleet`, `/fleet/summary`, `POST /fleet/heartbeat` + Prometheus fleet gauges

### Known gaps (intentionally later)
- Full YARA-X engine, kernel ETW/eBPF hooks
- System DNS hijack, embedded boringtun
- Full OIDC discovery / JWKS IdP
