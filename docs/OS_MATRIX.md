# S2O Aegis — OS portability matrix

Portability is a **P1 foundation requirement** (seams), not a P5 afterthought.  
Feature **parity** is not required until later phases.

---

## Target OS lines

| Family | Primary targets | P1 bar | Notes |
|--------|-----------------|--------|-------|
| **Windows** | 10/11, Server | Concrete (Wall T0) | First pour; COM `INetFwPolicy2` via `s2o_net_lib` |
| **Linux** | systemd Debian/RHEL-class | Build + Wall partial→real | nftables / firewalld; no fake full stack |
| **macOS** | current stable | Build + honest partial | `socketfilterfw` / NE constraints; say `unsupported` when true |
| **FreeBSD** | optional later | Out of P1 critical path | `pf` when scheduled |
| **Headless / cloud** | same kernels | Kernel + CLIs only | GUI console optional |

**OS implementation order:** Windows → Linux → macOS → BSD.

---

## Backend pattern (portable seams)

```text
world-core          # traits, models, errors (no OS calls)
backend-windows     # cfg(windows) or selected at runtime
backend-linux
backend-macos
backend-unsupported # compiles everywhere; returns clear errors
```

Kernel selects backend by OS. Worlds never sprinkle `#[cfg]` through business logic if a backend crate can own it.

---

## Health states (honesty)

Every world × OS reports something like:

| `state` | Meaning |
|---------|---------|
| `implemented` | Real OS effect for claimed commands |
| `partial` | Some commands real; others not |
| `not_implemented` | Slot exists; no real engine yet |
| `unsupported_on_os` | Will not ship on this OS (by design or platform limit) |
| `degraded` | Implemented but failing (perms, missing tool) |
| `demo` | Only if `AEGIS_DEMO=1` — never default |

Status JSON should include: `product`, `state`, `os`, `tier_ceiling`, `detail`.

---

## World × OS expectation (P1)

| World | Windows | Linux | macOS |
|-------|---------|-------|-------|
| Cyberwall | `implemented` (T0) | `partial` → `implemented` | `partial` / `unsupported_on_os` |
| CyberDNS | `partial` (DoH) | `partial` | `partial` |
| CyberDefender | `partial` / stub | stub | stub |
| CyberEDR | `partial` (IP Helper) | stub | stub |
| CyberLog | `partial` (JSONL read) | same | same |
| ThreatGrid | `not_implemented` | same | same |
| CyberID | `partial` (posture signals) | stub | stub |
| CyberMesh | `not_implemented` | same | same |
| Gate | `not_implemented` | same | same |
| **Kernel** | required | required | required |

---

## Tier × OS notes

| Tier | Windows | Linux | macOS |
|------|---------|-------|-------|
| T0 | Firewall COM, Defender APIs, IP Helper, DoH | nft/firewalld, resolvers, tools | limited PF CLI / app firewall |
| T1 | Services, ETW, MSI/signed bins | systemd units, auditd, eBPF *consumer* | launchd, EndpointSecurity (entitlements) |
| T2 | Callouts, divert product, signing cost | shipped eBPF products | heavily constrained; often skip |

T2 is not part of early portability success. T0 seams that compile and report honestly **are**.

---

## Build topology

Canonical lines layout (preferred):

```text
lines/s2o/
  aegis-console/     # this repo
  net-lib/           # s2o_net_lib — Windows policy adapters
```

Path deps must resolve from the active checkout. Until fixed, workspace load fails — treat topology as P1 stream E.

Adapters that are Windows-only stay behind `cfg(windows)` or optional deps so Linux/macOS `cargo check` still works for kernel + stubs.
