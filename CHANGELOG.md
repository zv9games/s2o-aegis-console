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
- Fleet policy distribution: `aegis fleet policy set|show|apply|push|pull`, aegisd `GET/POST /fleet/policy`
- Heartbeat returns `desired_policy_version` / `policy_stale`; roster tracks host `policy_version`
- Gate JWT RS256 + JWKS file (`jwt keygen`, `--jwt-jwks`); still no remote OIDC discovery
- Gate remote JWKS URL (`--jwt-jwks-url`, `jwt fetch-jwks`) with multi-key JWKS set
- CyberMesh peer registry: `peers list|add|remove|live|publish|pull` + multi-peer conf
- aegisd console API aliases `/api/v1/*`, `/posture`, `/events`, `/mesh/peers`
- OIDC discovery: Gate `--oidc-issuer`, `jwt oidc-discover`, iss validation
- aegisd lab IdP stub: `/.well-known/openid-configuration` + `/jwks.json`
- CyberDNS `system-dns show|backup|set|restore` (OS resolver bind + backup)
- CyberEDR `ps --rich` / `watch --rich` (cmdline + parent PID via WMI/ps)
- OAuth 2.0 device-code (RFC 8628 lab): aegisd `/oauth/device_*` + `cyberztna oauth device|approve`
- CyberDefender YARA-X (VirusTotal pure-Rust `yara-x` 1.19): `yara init|list|test|scan`, `scan --yara|--yara-only`, lab seed `.aegis/yara/*.yar`
- Cyberwall Windows `apply_policy`: managed netsh rules (`S2O-Aegis-*`), `cyberwall apply [--dry-run]`, suite policy `firewall.rules[]`
- OAuth authorization-code grant (lab): aegisd `GET/POST /oauth/authorize`, token `grant_type=authorization_code`, `cyberztna oauth code`
- CyberLog live collect: UDP syslog ingest (`cybersiem collect --listen`) → JSONL; PRI severity map; `--stdin-once` lab inject
- ThreatGrid multi-feed online sync: URLHaus + OpenPhish (capped per feed), `--feed` repeatable
- Multi-process event bus: `POST /events` + `aegisd --event-udp`, `s2o-bus` UDP relay, `aegis emit [--http] [--udp]`
- CyberDNS allowlist: `allow|unallow|list --allow`, overrides blocklist+IOC in resolve/serve; policy `allow_domains`
- CyberEDR `listen [--risk-only]`: TCP LISTEN inventory from userspace table
- Linux Cyberwall `apply_policy`: firewalld rich-rules or nft `inet s2o_aegis` managed table
- CyberMesh `doctor`: validate private key, conf, peers registry, wg tools
- Playbook actions: `emit`, `dns_allow` / `dns_allow_attr`
- CyberDefender quarantine ops: `quarantine list|restore|purge`
- macOS Cyberwall `apply_policy`: socketfilterfw managed app block/unblock (path rules)
- CyberDNS serve query stats (`--stats-secs`); CyberDefender `yara pull` URL ruleset fetch (capped)
- Expanded `aegis selftest` (event append, ingest decode, UDP bus, wall prefix, quarantine dir)
- aegisd Prometheus ingest counters (`aegis_event_ingest_total` http/udp ok|err)
- Fleet `prune [--stale-minutes] [--apply]` drop stale hosts
- CyberID `doctor` posture + session store health
- CyberDNS multi-resolver DoH (Cloudflare → Google `/resolve`, `--doh` chain) + fallback stat
- Gate `access-stats` on access log (allow/deny, reasons, paths, `--json`)

### Known gaps (intentionally later)
- Kernel ETW/eBPF hooks, realtime FS minifilter, commercial YARA feed
- Transparent DNS redirector, embedded boringtun
- Production browser IdP UI (lab authorize HTML + CLI auto-approve only)
- Remote SIEM EPS / multi-tenant collectors / gRPC bus
- macOS port-based rules / NEFilter
