# S2O Aegis Build Plan

_Last updated: 2026-10-18 (Phase 1 cleanup, branch `cleanup/phase1`)._

This file tracks what exists in the code, not marketing. Status words match the README.

## Current state

| Pillar | Crate | Status | Notes |
| --- | --- | --- | --- |
| Cyberwall | `cyberwall-core`, `cyberwall-backend-windows`, `cyberwall-backend-linux`, `cyberwall-cli` | Working (Win) / Partial (Linux) | Windows via `netsh` + NetSecurity cmdlets (`s2o-platform::firewall`). `apply_policy` returns not-implemented on all OSes. Linux: status probe only; control methods return errors. |
| CyberMesh | `cybermesh` | Partial | Real X25519 keys (x25519-dalek), WireGuard config export, local peer list. No tunnel management or peer exchange. Private key stored in plaintext at `.aegis/mesh_config.json`. |
| CyberDefender | `cyberdefender` | Working (Win) | SHA-256 scan against a tiny built-in list (EICAR etc.); Defender status/scan/update via `s2o-platform::defender`. |
| CyberEDR | `cyberedr` | Working | Socket table via `s2o-platform::telemetry` (netstat on Windows, /proc on Linux), suspicious ports, polling watcher. |
| CyberSIEM | `cybersiem`, `s2o-store`, `s2o-schema` | Working (local) | JSONL append store; query/tail/stats/export. Single host only. |
| CyberIntel | `cyberintel` | Working (on demand) | URLhaus CSV pull into local JSON DB; lookup/add/list. |
| CyberDNS | `cyberdns` | Partial | Cloudflare DoH lookups, blocklist, `serve` UDP forwarder (not installed as a resolver). |
| CyberID | `cyberid` | Working (Win) | 4-check posture score (30/30/20/20). Ed25519 JWS tokens, per-host key at `.aegis/cyberid_ed25519.key`, `verify`/`pubkey`. |
| CyberZTNA | `cyberztna` | Planned | Route store + local posture preflight only. No proxy. |
| Daemon / CLI / IPC | `aegisd`, `aegis-cli`, `s2o-bus` | Partial | aegisd probes firewall/Defender/sockets, logs a health event, serves `ping`/`status` over named pipe / Unix socket. `reload` not implemented. aegisd `start` needs Windows (firewall probe errors elsewhere). |
| Platform layer | `s2o-platform` | New | Replaces the out-of-tree `net-lib`. `PacketBackend` trait with `NoDriver` default; `packet-driver` feature reserves a slot for WinDivert / future CA-signed driver (binding not implemented). |
| GUI | root package `s2o-aegis-gui` (`aegis-gui`) | Partial | egui 0.17 dashboard. Several actions run `cargo run -p ...`, so it only works from a source checkout. |

## Phase 1 (done on `cleanup/phase1`)
- Fresh clone builds: removed `../net-lib` path deps, added `s2o-platform`, reqwest on rustls.
- Real crypto in cybermesh and cyberid; removed unconditional posture points.
- Honest status output in aegisd, aegis-gui, aegis-cli, cyberztna, Linux firewall backend.
- README truth pass, full AGPL text + NOTICE, license fields, legacy prototypes removed.

## Phase 2 candidates (not started)
1. **Fleet control plane**: an `aegis-server` that enrolls agents (mutual TLS or signed enrollment tokens), receives SIEM events and posture tokens, and pushes policy. This is the core of "fleet security and observation".
2. **Policy engine**: implement `apply_policy` (Windows first), wire `aegisd reload`, versioned policy files.
3. **aegisd as a real service**: Windows service / systemd unit that supervises the pillar engines in-process instead of separate CLIs; GUI talks to it over IPC instead of `cargo run`.
4. **Packet driver binding**: implement `DriverBackend` for WinDivert 2.2 behind `packet-driver`; later swap in the CA-signed custom driver with the same trait.
5. **Linux parity**: nftables rule control, posture checks, then eBPF telemetry.
6. **CyberZTNA proxy**: TCP reverse proxy with mTLS, gated on CyberID tokens verified against fleet keys.
7. **CyberMesh**: drive WireGuard (wireguard-nt / `wg` / boringtun), peer exchange via the control plane, protect stored private keys (DPAPI / file perms).
8. **macOS backend** (pfctl, Endpoint Security) once Windows/Linux are solid.
9. **CI**: GitHub Actions running check/test/clippy on Windows and Linux.
10. **GUI**: fix CLI argument mismatches (`gen-key` vs `genkey`, `lookup` vs `resolve`, `cyberedr audit` does not exist), upgrade egui 0.17.
