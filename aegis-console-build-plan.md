# S2O Aegis Platform: 9-Pillar Cybersecurity Console & Engine Build Plan

**Document Version:** 1.0.0  
**Target Platform:** Windows 10/11 / Windows Server (Primary), Linux (`nftables`/`eBPF`) & FreeBSD (`pf`) (Cross-target)  
**License / Cost Model:** **Tier 0 ($0/yr recurring cost)** — zero driver-signing taxes, leveraging userspace APIs (COM `INetFwPolicy2`, WFP User API, IP Helper, Windows Defender COM/WMI, DoH/DoT, BoringTun WireGuard userspace).  
**Core Architectural Transition:** Transitioning completely from legacy `xallfirewall` WinDivert GUI experiments to `cyberwall` and the unified 9-pillar `aegisd` enterprise suite.

---

## 1. Executive Summary & The 9 Pillars

S2O Aegis is structured as an orchestrator service (`aegisd`) backed by shared event schemas (`s2o-schema`), an event store (`s2o-store`), and an IPC bus (`s2o-bus`), coordinating 9 dedicated cybersecurity disciplines:

```
+-----------------------------------------------------------------------------------------+
|                        S2O AEGIS CONSOLE / COMMAND PLANE                                |
|             (CLI / Aegis Console Dashboard / IPC Client / Event Stream)                |
+-----------------------------------------------------------------------------------------+
                                             |
                                    [\\.\pipe\s2o_aegis_ipc]
                                             v
+-----------------------------------------------------------------------------------------+
|                      aegisd — Master Cyber-Ops Service Daemon                           |
|       (Event Dispatcher, Health Evaluator, Policy Engine, s2o-bus / s2o-store)          |
+-----------------------------------------------------------------------------------------+
   |         |         |         |         |         |         |         |         |
   | 1       | 2       | 3       | 4       | 5       | 6       | 7       | 8       | 9
   v         v         v         v         v         v         v         v         v
+-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +-------+
| CYBER | | CYBER | | CYBER | | CYBER | | CYBER | | THREAT| | CYBER | | CYBER | | CYBER |
| WALL  | | MESH  | | DEFNDR| |  EDR  | | SIEM  | | GRID  | |  DNS  | |  ID   | | ZTNA  |
| (FW)  | | (VPN) | | (AV)  | |(Detect| | (Logs)| |(Intel)| |(Guard)| | (IAM) | | (Gate)|
+-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +-------+
```

| # | Pillar Engine | Binary / Subsystem | Current State | Target State |
|---|---|---|---|---|
| **1** | **Cyberwall** | `cyberwall` | Profile status, global enable/disable, lock | Full Rule CRUD (port, IP, app), profile granularity, live filtering audit |
| **2** | **CyberMesh** | `cybermesh` | Mock keys only | Userspace WireGuard (BoringTun / Wintun), peer configuration, mesh heartbeat |
| **3** | **CyberDefender** | `cyberdefender` | SHA-256 single-file hash | Recursive scanner, signature hash-set verification, Defender WMI/PowerShell integration |
| **4** | **CyberEDR** | `cyberedr` | Static snapshot of IP Helper TCP table | Live TCP socket connection watcher correlated with PID, executable path, process name, and threat flags |
| **5** | **CyberSIEM** | `cybersiem` | Dump JSONL events from file | High-throughput structured event stream, Syslog/NDJSON exporter, event ingestion from all 9 engines |
| **6** | **ThreatGrid** | `cyberintel` | CLI stubs (`not implemented`) | Offline IOC feeds (Abuse.ch, URLhaus, OpenPhish) loaded into SQLite/bloom filter, high-speed IOC lookup |
| **7** | **CyberDNS** | `cyberdns` | Single Cloudflare DoH query | Local forwarding DNS proxy (`127.0.0.1:53`), local sinkhole/blocklist, upstream DoH/DoT |
| **8** | **CyberID** | `cyberid` | Static 2-metric posture check (50/100) | Full zero-trust posture evaluation (BitLocker status, OS build, UAC, Defender, Firewall, secure boot) |
| **9** | **CyberZTNA** | `cyberztna` | CLI stubs (`not implemented`) | Local reverse proxy with mTLS and posture gating before granting network tunnel access |
| **D** | **Aegis Master** | `aegisd` | CLI status probe | Persistent background service, named pipe IPC server, automated event emitter, health aggregation |
| **C** | **Console GUI**| `aegis-console` | Outdated `xallfirewall` egui 0.17 | Modern egui dashboard connected via IPC to `aegisd` displaying the live 9-pillar matrix |

---

## 2. Phased Build Roadmap

---

### Phase 1: Firewall Mastery & Workspace Cleanup
**Focus:** Elevate `cyberwall` to a production-grade policy engine and formally rebrand the workspace from `xallfirewall` to `aegis-console`.

#### Work Items:
1. **Workspace & Root Rebrand:**
   * Rename root package from `xallfirewall` to `aegis-console` (or dedicate root to the modern unified dashboard).
   * Archive legacy WinDivert experiments (`interface1..4.rs`, `cyber_firewall.rs`, `network_wireframe.rs`) into `legacy/` or remove from active `[[bin]]` list.
2. **`cyberwall-core` Rule Model Expansion:**
   * Define `FirewallRule` struct: Name, Direction (Inbound/Outbound), Action (Allow/Block), Protocol (TCP/UDP/Any), LocalPorts, RemotePorts, LocalAddresses, RemoteAddresses, ApplicationPath, Enabled, Profile.
3. **`cyberwall-backend-windows` Implementation:**
   * Extend `WindowsFirewallEngine` with COM `INetFwRules` interface:
     * `add_rule(rule: &FirewallRule) -> Result<()>`
     * `delete_rule(rule_name: &str) -> Result<()>`
     * `list_rules(filter: Option<RuleFilter>) -> Result<Vec<FirewallRule>>`
     * `set_profile_state(profile: ProfileType, enabled: bool) -> Result<()>`
   * Robust fallback to `netsh advfirewall firewall ...` if COM automation encounters permissions or HRESULT issues.
4. **`cyberwall-cli` Commands:**
   * `cyberwall rules list [--inbound] [--outbound] [--port <PORT>]`
   * `cyberwall block-port <PORT> [--protocol tcp|udp] [--name <NAME>]`
   * `cyberwall block-ip <IP_ADDR> [--name <NAME>]`
   * `cyberwall block-app <APP_PATH> [--name <NAME>]`
   * `cyberwall allow-port <PORT>` / `allow-app <APP_PATH>`
   * `cyberwall delete-rule <NAME>`
   * Emit `AegisEvent` on rule creation/deletion to `s2o-bus`.

---

### Phase 2: Local Edge Defenses (`cyberdns` & `cyberdefender`)
**Focus:** Build real, actionable network filtering and file threat checking without kernel drivers.

#### Work Items:
1. **`cyberdns` Local Proxy & Threat Sinkhole:**
   * **Local DNS Listener:** Implement UDP socket server listening on `127.0.0.1:53` (or configurable port, e.g. `127.0.0.1:5353`).
   * **DoH Upstream Dispatch:** Parse incoming DNS query wire format (using lightweight DNS packet parser or `trust-dns-proto`), forward query over HTTPS to Cloudflare (`1.1.1.1`) or Quad9 (`9.9.9.9`), and return DNS response to local client.
   * **Sinkhole Engine:** Implement local blocklist evaluation (`s2o-store`). If query matches known malicious domain, immediately return `0.0.0.0` / `NXDOMAIN`.
   * **CLI Updates:**
     * `cyberdns serve [--listen 127.0.0.1:53] [--upstream doh|dot]`
     * `cyberdns block <DOMAIN>` (adds to local sinkhole DB)
     * `cyberdns unblock <DOMAIN>`
     * `cyberdns list-blocked`
2. **`cyberdefender` Scanner & Windows Defender Automation:**
   * **Directory Traversal Scanner:** Multi-threaded recursive scanner calculating SHA-256 hashes with progress reporting.
   * **Known Malicious Hash Store:** Store known bad hashes in local SQLite/bloom filter (`s2o-store`) to identify known test signatures (e.g. EICAR test string, known bad hashes).
   * **Windows Defender WMI/PowerShell Interface:**
     * Query real Defender status: engine version, signatures updated date, real-time protection state (`Get-MpComputerStatus`).
     * `cyberdefender scan-quick` / `scan-full` triggering native Windows Defender scans via PowerShell `Start-MpScan`.
     * `cyberdefender update-defs` triggering `Update-MpSignature`.

---

### Phase 3: Telemetry, EDR & SIEM Pipeline (`cyberedr` & `cybersiem`)
**Focus:** Correlate live process sockets and build high-throughput event streaming.

#### Work Items:
1. **`cyberedr` Process & Network Correlation Engine:**
   * Correlate IP Helper socket table with Windows Process API (`OpenProcess`, `QueryFullProcessImageNameW`).
   * For every open socket, report:
     * Local IP:Port, Remote IP:Port, State (ESTABLISHED, LISTENING, etc.).
     * Owning PID, Process Name (e.g., `svchost.exe`, `chrome.exe`, `curl.exe`), Full Path, and Process Architecture.
   * **Live Connection Monitor (`cyberedr watch`):**
     * Polling loop or diff engine detecting newly spawned outbound connections.
     * Flag suspicious ports (e.g. outbound 4444, 1337, or non-standard SSH/RDP).
     * Publish `AegisEvent::new(..., ProductId::CyberEdr, EventKind::NetFlow, ...)` to `s2o-bus`.
2. **`cybersiem` Event Pipeline & Exporters:**
   * Ingest all events from `.aegis/events.jsonl` and the in-memory bus.
   * Add query filtering CLI:
     * `cybersiem query --product cyberwall --since 1h`
     * `cybersiem stats --group-by severity`
     * `cybersiem export --format syslog|ndjson|csv --out <FILE>`
   * **Realtime Follower:** `cybersiem tail -f` (similar to `tail -f`, printing colorized live events as they arrive).

---

### Phase 4: Threat Intelligence & Posture Engine (`cyberintel` & `cyberid`)
**Focus:** Integrate automated reputation lookups and granular zero-trust posture health.

#### Work Items:
1. **`cyberintel` ThreatGrid Feed Aggregator:**
   * **Local IOC Database:** Create local SQLite database for threat intelligence storing IPs, Domains, and File Hashes with confidence scores.
   * **Feed Ingestion (`cyberintel sync`):**
     * Ingest open-source feeds (e.g., URLhaus recent CSV, Abuse.ch Feodo Tracker IP blocklist).
     * Store metadata: date added, malware family, threat rating.
   * **Lookup Command (`cyberintel lookup <IP|DOMAIN|HASH>`):**
     * Instant local indexed query returning reputation score, associated malware tags, and first/last seen timestamps.
   * Auto-link with `cyberdns` and `cyberwall` (option to block identified malicious IPs in Cyberwall automatically).
2. **`cyberid` Zero-Trust Posture Evaluator:**
   * Replace the simple 2-check mock with a comprehensive Windows posture audit:
     * **Firewall Check:** Is Windows Firewall active across all 3 profiles? (Weight: 20 pts)
     * **AV Check:** Is Windows Defender or registered AV active and definitions < 3 days old? (Weight: 20 pts)
     * **BitLocker / Encryption Check:** Query `manage-bde` / WMI `Win32_EncryptableVolume` for OS drive encryption. (Weight: 20 pts)
     * **Secure Boot Check:** Query Registry / UEFI for SecureBoot enabled status. (Weight: 15 pts)
     * **UAC Status:** Query registry `EnableLUA` (User Account Control). (Weight: 15 pts)
     * **Pending OS Updates:** Check Windows Update agent state. (Weight: 10 pts)
   * Output posture score (0–100) with detailed remediation recommendations for any failing category.

---

### Phase 5: Mesh VPN & Zero Trust Network Access (`cybermesh` & `cyberztna`)
**Focus:** Build secure overlay networking and micro-segmentation access.

#### Work Items:
1. **`cybermesh` Overlay WireGuard VPN:**
   * Replace placeholder random strings with true X25519 / Curve25519 key generation (`x25519-dalek`).
   * Implement userspace WireGuard configuration generator (`cybermesh gen-config`):
     * Generates valid WireGuard `.conf` files compatible with standard WireGuard Windows client and BoringTun.
   * Status integration: Query active network adapters for WireGuard interfaces (`wg0`) and parse active handshake telemetry and transfer bytes.
2. **`cyberztna` Application Micro-Segmentation Gateway:**
   * Implement a lightweight local HTTP/TCP reverse proxy using `hyper` / `tokio`.
   * **Posture Gate:** Before routing connection to local protected service (e.g. localhost internal API), verify that `cyberid posture` score meets minimum policy threshold (e.g. >= 80).
   * Log all access grants and denials to `cybersiem`.

---

### Phase 6: Orchestration Master Daemon (`aegisd`) & IPC Bus
**Focus:** Unify all 9 engines under a live daemon communicating via Named Pipes.

#### Work Items:
1. **Windows Named Pipe IPC (`s2o-bus`):**
   * Server path: `\\.\pipe\s2o_aegis_ipc` (Windows) and `/run/aegisd.sock` (Linux).
   * Request/Response RPC protocol: JSON-RPC or length-prefixed JSON schema.
   * Commands: `GetStatus`, `TriggerScan`, `ApplyRule`, `QueryIoc`, `StreamEvents`.
2. **`aegisd` Background Daemon:**
   * Runs continuously as a Windows Service (or CLI worker with `aegisd run`).
   * Periodically polls engine health (Firewall status, Defender status, DNS proxy health, EDR socket watch).
   * Serves as the central publisher writing to `.aegis/events.jsonl`.
   * Dispatches commands from the Console or CLIs down to specific subsystem engines.

---

### Phase 7: Unified Aegis Command Center Dashboard
**Focus:** Modern, real-time GUI command center replacing the obsolete prototypes.

#### Work Items:
1. **Modern egui Dashboard (`aegis-console`):**
   * Update GUI crate to modern `egui` (or separate desktop client).
   * **Overview Matrix:** 9 interactive live cards showing the status of each pillar (Green/Yellow/Red, metrics, quick action buttons).
   * **Firewall Manager Tab:** Table of active rules with 1-click toggle, Add Rule dialog, and Emergency Isolation Shield switch.
   * **Live Telemetry & EDR View:** Real-time scrolling table of process connections with suspicious indicators highlighted.
   * **SIEM Stream:** Live visual log tail with severity coloring and search/filter bar.
   * **Zero-Trust Posture Dial:** Circular posture health meter (0–100) with pass/fail breakdown.
2. **IPC Integration:** Connect dashboard directly to `aegisd` over named pipe for sub-millisecond updates without heavy process spawning.

---

## 3. Immediate Next Execution Slices

To begin making tangible progress immediately, the work can proceed in small, verifiable slices:

* **Slice 1:** Update `Cargo.toml` & file layout to retire the broken `xallfirewall` experiments and establish `cyberwall` as the primary workspace package.
* **Slice 2:** Add Rule Creation, Deletion, and Listing to `cyberwall-backend-windows` and expose them via `cyberwall rules` and `cyberwall block-port`.
* **Slice 3:** Implement recursive hashing + Windows Defender PowerShell query in `cyberdefender`.
* **Slice 4:** Implement `cyberdns serve` local proxy with Cloudflare DoH and blocklist filtering.
