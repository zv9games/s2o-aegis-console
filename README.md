<p align="center">
  <img src="https://raw.githubusercontent.com/zv9games/s2o-aegis-console/main/assets/aegis_banner.png" alt="S2O Aegis Banner" width="100%" onerror="this.style.display='none'"/>
</p>

# S2O AEGIS: The Universal Cyber-Ops Substrate
### *Unbreakable Sovereignty for the Modern Operating System.*

[![Rust](https://img.shields.io/badge/Language-Pure%20Rust%202021-DEA584?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Substrate](https://img.shields.io/badge/Substrate-Tier--0%20Userspace%20Native-00E696?style=for-the-badge)](https://split2ops.com)
[![Kernel Readiness](https://img.shields.io/badge/Kernel%20Driver-Standby%20Ready-64C8FF?style=for-the-badge)](https://split2ops.com)
[![Footprint](https://img.shields.io/badge/Memory%20Footprint-%3C%2035%20MB-blueviolet?style=for-the-badge)](https://split2ops.com)
[![License](https://img.shields.io/badge/License-Dual%20AGPLv3%20%2F%20Commercial-FF4B4B?style=for-the-badge)](LICENSE)

---

## The Genesis: Why Aegis Exists

The enterprise cybersecurity landscape is fractured, bloated, and perilous:
* **The "CrowdStrike Paradox"**: Heavy, fragile kernel-mode drivers crash millions of endpoints worldwide, causing billions in downtime.
* **The 7-Agent Tax**: Organizations deploy 5 to 7 disconnected agents eating 2–4 GB of RAM, causing lag, thermal throttling, and internal telemetry collision.
* **The Black Box Lie**: Closed proprietary agents conceal vulnerabilities and leak system telemetry to third-party clouds.

**S2O Aegis is the cure.** Engineered from the gods in high-performance Rust, Aegis replaces fragmented legacy sprawl with a **single, unified, mathematical fortress**.

Operating under a **Tier-0 Userspace Architecture ($0/year recurring driver fees)**, Aegis delivers 9 enterprise security disciplines through direct native OS calls (`INetFwPolicy2`, WFP User API, IP Helper, Cloudflare DoH, Curve25519) with a RAM footprint of **under 35 MB**.

When your organization demands low-level packet ring-0 inspection, Aegis features a **pluggable driver abstraction layer** that connects to a Windows Kernel-Mode Callout Driver (`.sys`), Linux eBPF, or Apple NetworkExtension on demand without changing a single line of business logic.

---

## The 9 Pillars of Aegis

Aegis consolidates an entire Security Operations Center (SOC) stack into a unified matrix:

```
                      ┌─────────────────────────────────────────────────────────────┐
                      │              S2O AEGIS COMMAND SUBSTRATE                    │
                      │        (Unified Master CLI 'aegis' & Executive GUI)        │
                      └──────────────────────────────┬──────────────────────────────┘
                                                     │
                             ┌───────────────────────┴───────────────────────┐
                             ▼                                               ▼
                  [ Universal IPC Bus ]                           [ 9 Pillar Matrix ]
                  Named Pipe / Unix Sock                          Zero-Bloat Rust Engines
                             │                                               │
    ┌────────────────────────┴───────────────────────────────────────────────┴────────────────────────┐
    │                                                                                                  │
    ▼           ▼             ▼             ▼            ▼            ▼           ▼            ▼       ▼
 [CYBERWALL] [CYBERMESH] [CYBERDEFENDER] [CYBEREDR] [CYBERLOG] [THREATGRID] [CYBERDNS] [CYBERID] [CYBERZTNA]
  Firewall    WireGuard   AV Scanner    Socket EDR   SIEM Stream   IOC Intel   DoH Sinkhole PAM Posture SASE Gate
```

| Pillar | Engine | Discipline | Technical Substrate |
| :---: | :--- | :--- | :--- |
| **I** | **S2O Cyberwall** | Stateful OS Firewall | Direct Win32 COM `INetFwPolicy2` rules orchestration, instant inbound/outbound isolation lockdown. |
| **II** | **S2O CyberMesh** | Cryptographic Overlay Mesh | WireGuard peer-to-peer virtual private mesh network using Curve25519 & ChaCha20-Poly1305. |
| **III** | **S2O CyberDefender** | Endpoint Antivirus | Recursive filesystem SHA-256 integrity scanner + live Windows Defender engine query via WMI. |
| **IV** | **S2O CyberEDR** | Process & Socket Telemetry | Correlates live IP Helper network sockets with Windows PIDs & image paths. Backdoor port detector. |
| **V** | **S2O CyberLog** | Enterprise SIEM | Lock-free high-throughput event ringbuffer logging structured JSONL telemetry to `.aegis/events.jsonl`. |
| **VI** | **S2O ThreatGrid** | Threat Intelligence | Local high-speed IOC database synchronized in real-time with Abuse.ch URLhaus malware feeds. |
| **VII** | **S2O CyberDNS** | DNS Shield & Sinkhole | Encrypted DNS-over-HTTPS (DoH) resolver + local malware/telemetry sinkhole proxy. |
| **VIII** | **S2O CyberID** | Zero-Trust PAM / IAM | 5-Pillar endpoint posture auditor (Firewall, AV, UAC, SecureBoot, Isolation) with signed JSON tokens. |
| **IX** | **S2O ZTNA Gateway** | Micro-Segmentation Proxy | Zero-Trust Network Access reverse proxy enforcing endpoint posture compliance preflight. |

---

## Architectural Breakthrough: The Universal Substrate

Unlike legacy agents that tie their logic to OS idiosyncrasies, Aegis is built on the **Universal Security Substrate (USS)**:

1. **Multi-OS Native by Design**:
   * **Microsoft Windows**: Userspace COM/WFP/IPHelper today $\rightarrow$ Kernel Driver (`.sys`) tomorrow.
   * **Linux**: `nftables`/`iptables`/ProcFS today $\rightarrow$ Kernel **eBPF (XDP + TC + LSM)** tomorrow.
   * **macOS (Darwin)**: `pfctl`/`scutil` today $\rightarrow$ Apple **EndpointSecurity & NetworkExtension** tomorrow.
2. **Universal Inter-Process Communication (IPC)**:
   * **Windows**: High-speed Named Pipe (`\\.\pipe\s2o_aegis_ipc`).
   * **Unix / Linux / macOS**: Non-blocking Unix Domain Socket (`/tmp/s2o_aegis.sock`).
   * Unified JSON-RPC client-daemon protocol with zero disk wear.
3. **Zero Kernel Crash Liability**:
   * Operates completely in userspace with administrative privileges. It cannot trigger a Blue Screen of Death (BSOD) or kernel panic.

---

## Executive Command Center GUI

Aegis includes an executive management dashboard written in GPU-accelerated **`egui`**:

* **Auto-Maximized Fullscreen Console** (minimum 800x600 failsafe).
* **Live 9-Pillar Operational Matrix** with real-time health indicators.
* **Deep Customization Windows per Pillar**:
  * Create, inject, and delete custom firewall rules on the fly.
  * Generate and export WireGuard configuration profiles.
  * Set backdoor alert thresholds and force-kill rogue PIDs.
  * Block and unblock domains in the local DNS sinkhole.
  * Enforce hardware UEFI SecureBoot and Windows UAC posture policies.
* **Real-Time SIEM Event Stream** displaying live telemetry as it happens.

Launch the Command Center:
```powershell
cargo run --bin aegis-gui
```

---

## Master Multiplexer CLI (`aegis`)

Control every aspect of Aegis through a single master binary:

```powershell
# Inspect the entire platform, active OS, and driver substrate
aegis status

# Deep 5-Pillar Zero-Trust Posture Audit
aegis posture

# Next-Gen Firewall Control
aegis firewall enable
aegis firewall block-port 4444 --protocol TCP
aegis firewall block-ip 198.51.100.1
aegis firewall list

# Filesystem Malware & Integrity Scanning
aegis scan C:\Windows\System32

# Encrypted DNS Query & Threat Sinkhole
aegis dns resolve split2ops.com
aegis dns block malicious-c2.com

# EDR Process & Socket Telemetry
aegis edr sockets
aegis edr audit

# Inter-Process Daemon Communication
aegis daemon ping
aegis daemon status
```

---

## Commercial Dual-Licensing Model

S2O Aegis is released under an **Open-Core / Dual-License** strategy:

### 1. Community Edition (AGPLv3)
* **Free and open-source** for security researchers, homelab enthusiasts, and individuals.
* Source code is fully auditable to guarantee **zero telemetry backdoors**.
* Copyleft protections prevent proprietary SaaS providers from re-hosting without contributing modifications back to the community.

### 2. Commercial Enterprise License
Designed for **Managed Service Providers (MSPs), Financial Institutions, and Enterprise Fleets** needing:
* Proprietary distribution rights without AGPLv3 copyleft reciprocity.
* Closed-source commercial OEM / appliance embedding.
* Dedicated SLA, custom Windows Kernel Driver (`.sys`) development, and cloud fleet orchestration.
* Priority threat intelligence feeds and custom enterprise compliance modules.

For commercial licensing and enterprise procurement inquiries:
📧 **Email:** [enterprise@split2ops.com](mailto:enterprise@split2ops.com)  
🌐 **Website:** [https://split2ops.com](https://split2ops.com)

---

<p align="center">
  <b>S2O Aegis — Unmatched Speed. Infinite Scalability. Absolute Security Sovereignty.</b><br/>
  <i>Copyright © 2026 Split2ops Software. All rights reserved.</i>
</p>
