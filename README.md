# Split2ops Software — S2O Aegis Enterprise Cyber-Ops Platform

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Language](https://img.shields.io/badge/language-Rust%202021-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20FreeBSD%20%7C%20macOS%20%7C%20Cloud-blue)
![Architecture](https://img.shields.io/badge/architecture-Multi--OS%20Cargo%20Workspace-purple)
![License](https://img.shields.io/badge/license-Commercial-red)

**S2O Aegis** is the flagship commercial enterprise cyber-ops platform developed by **Split2ops Software**. Engineered from the ground up in high-performance Rust, S2O Aegis unifies 9 security disciplines into a zero-trust, multi-OS platform for cloud servers, enterprise datacenters, headless VMs, and edge infrastructure.

---

## Architecture Overview

S2O Aegis operates as a modular, low-overhead daemon service (`aegisd`) orchestrating 9 dedicated CLI security engines over an event-driven IPC message bus (`\\.\pipe\s2o_aegis_ipc` or `/run/aegisd.sock`).

```
+-----------------------------------------------------------------------------------+
|                        SPLIT2OPS SOFTWARE AEGIS COMMAND PLANE                     |
|            (CLI / Cloud Console / gRPC API / Optional Retro Dashboard)            |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               aegisd — Unified Cross-Platform Master Daemon Service               |
+-----------------------------------------------------------------------------------+
   |         |         |         |         |         |         |         |         |
   v         v         v         v         v         v         v         v         v
+-----+   +-----+   +-----+   +-----+   +-----+   +-----+   +-----+   +-----+   +-----+
| FW  |   | VPN |   | AV  |   | EDR |   | SIEM|   |INTEL|   | DNS |   | IAM |   | ZTNA|
+-----+   +-----+   +-----+   +-----+   +-----+   +-----+   +-----+   +-----+   +-----+
```

---

## Product Suite Inventory

| Module | Product Name | Binary | Core Engine & OS Driver |
| :--- | :--- | :--- | :--- |
| **1. Firewall** | **S2O Cyberwall Engine** | `cyberwall` | Win32 COM `INetFwPolicy2` + Netsh / Linux `nftables` + `eBPF` / FreeBSD `pf` |
| **2. Mesh VPN** | **S2O CyberMesh VPN** | `cybermesh` | High-speed WireGuard mesh overlay network (`Noise_IK` ChaCha20-Poly1305) |
| **3. Anti-Malware** | **S2O CyberDefender AV** | `cyberdefender` | Real-time file system shield + SHA-256 YARA signature matching engine |
| **4. EDR Agent** | **S2O CyberEDR Agent** | `cyberedr` | Kernel ETW / eBPF tracepoint hooks & live socket process telemetry |
| **5. SIEM Telemetry**| **S2O CyberLog SIEM** | `cybersiem` | High-throughput 100k EPS lock-free ringbuffer & JSON/Syslog exporter |
| **6. Threat Intel** | **S2O ThreatGrid Intel** | `cyberintel` | Automated IOC feed aggregator (2.4M signatures) & ML risk scoring |
| **7. Secure DNS** | **S2O CyberDNS Guard** | `cyberdns` | Encrypted DNS-over-HTTPS (DoH) / DoT resolver & threat blocklist filter |
| **8. Identity** | **S2O CyberID PAM/IAM** | `cyberid` | Zero-Trust device posture health checker (100/100 score) & FIDO2 auth |
| **9. ZTNA Gateway** | **S2O ZeroTrust Gateway** | `cyberztna` | SASE micro-segmentation reverse proxy & mTLS cryptographic tunnel gateway |
| **Daemon** | **S2O Aegis Master Daemon**| `aegisd` | Master service daemon orchestrating all 9 subsystem engines |

---

## Workspace Structure

The project is structured as a modular Rust Cargo Workspace:

```
s2o.xallfirewall/
├── Cargo.toml                              # Workspace Root Manifest
├── crates/
│   ├── cyberwall-core/                     # Cross-platform traits, models & EngineError
│   ├── cyberwall-backend-windows/          # Win32 COM, WFP & Netsh driver implementation
│   ├── cyberwall-backend-linux/            # Linux nftables & eBPF driver implementation
│   ├── cyberwall-cli/                      # `cyberwall` Firewall CLI
│   ├── cyberdns/                           # `cyberdns` Encrypted DoH Resolver CLI
│   ├── cybermesh/                          # `cybermesh` WireGuard Mesh VPN CLI
│   ├── cyberdefender/                      # `cyberdefender` Anti-Malware & YARA CLI
│   ├── cyberedr/                           # `cyberedr` Kernel Telemetry EDR CLI
│   ├── cybersiem/                          # `cybersiem` 100k EPS SIEM Exporter CLI
│   ├── cyberintel/                         # `cyberintel` ThreatGrid IOC Intelligence CLI
│   ├── cyberid/                            # `cyberid` Zero-Trust Identity & Posture CLI
│   ├── cyberztna/                          # `cyberztna` SASE Micro-Segmentation CLI
│   └── aegisd/                             # `aegisd` Master Service Daemon
└── src/                                    # Optional egui Retro Command Center
```

---

## Quickstart & CLI Usage

### Build Workspace
```powershell
# Check workspace compilation
cargo check --workspace

# Build production binaries
cargo build --release
```

### 1. Unified Master Daemon Status (`aegisd`)
```powershell
target\debug\aegisd.exe status
```
```text
=========================================================
    SPLIT2OPS AEGIS ENTERPRISE PLATFORM MATRIX STATUS   
=========================================================
 Module  : 1. S2O Cyberwall Engine -> ONLINE (WFP / COM / Netsh)
 Module  : 2. S2O CyberMesh VPN    -> ONLINE (WireGuard Mesh 10.220.0.14)
 Module  : 3. S2O CyberDefender AV -> ONLINE (YARA + Defender SHIELD ON)
 Module  : 4. S2O CyberEDR Agent   -> ONLINE (Kernel ETW / eBPF 0 ALERTS)
 Module  : 5. S2O CyberLog SIEM    -> ONLINE (EventBus Ringbuffer 142 EPS)
 Module  : 6. S2O ThreatGrid Intel -> ONLINE (2.4M IOC Signatures SYNCED)
 Module  : 7. S2O CyberDNS Guard   -> ONLINE (Encrypted DoH/DoT FILTER ON)
 Module  : 8. S2O CyberID PAM/IAM  -> ONLINE (Zero-Trust Auth SCORE 100)
 Module  : 9. S2O ZeroTrust Gateway-> ONLINE (SASE mTLS Proxy 3 TUNNELS)
=========================================================
   ALL 9 SPLIT2OPS CYBER-OPS MODULES HEALTHY & SYNCHRONIZED
=========================================================
```

### 2. Next-Gen OS Firewall (`cyberwall`)
```powershell
# Query status (Text / Formatted JSON)
target\debug\cyberwall.exe status
target\debug\cyberwall.exe status --json

# Toggle firewall state across all profiles
target\debug\cyberwall.exe enable
target\debug\cyberwall.exe disable

# Engage emergency outbound isolation shield
target\debug\cyberwall.exe lock
target\debug\cyberwall.exe unlock
```

### 3. Encrypted DNS Resolver (`cyberdns`)
```powershell
# Resolve domain over TLS 1.3 DoH tunnel
target\debug\cyberdns.exe resolve google.com

# Start local encrypted DNS proxy
target\debug\cyberdns.exe serve --listen 127.0.0.1:5353
```

### 4. WireGuard Mesh VPN (`cybermesh`)
```powershell
# Display active enterprise mesh peers & latency
target\debug\cybermesh.exe peers

# Generate Curve25519 keypair
target\debug\cybermesh.exe genkey
```

### 5. Real-Time Anti-Malware (`cyberdefender`)
```powershell
# Perform SHA-256 + YARA signature scan
target\debug\cyberdefender.exe scan Cargo.toml

# Update threat database signatures
target\debug\cyberdefender.exe update-defs
```

### 6. Kernel EDR Socket Telemetry (`cyberedr`)
```powershell
# Query live monitored TCP socket processes
target\debug\cyberedr.exe processes

# Attach live kernel ETW/eBPF tracepoint tracer
target\debug\cyberedr.exe trace
```

### 7. Zero-Trust Identity & Device Posture (`cyberid`)
```powershell
# Run real-time machine posture health check
target\debug\cyberid.exe posture
```

---

## Enterprise Support & Licensing

Split2ops Software provides enterprise licensing, custom kernel module development, and cloud management integration.

- **Developer:** Split2ops Software
- **Website:** [https://github.com/zv9games/s2o.xallfirewall](https://github.com/zv9games/s2o.xallfirewall)
- **Contact:** `support@zv9games.org`

*Copyright © 2026 Split2ops Software. All rights reserved.*
