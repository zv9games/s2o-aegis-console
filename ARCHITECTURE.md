# S2O Aegis Architecture

_Status: design document, 2026-10-18. Describes the target system and how far
the code is from it. Anything not marked **Exists** is not built yet._

## 1. Goal

A fleet IT security and observation suite that stays safe when **any single
component is compromised**: the fleet server, the network, or one admin.
Observation (inventory, posture, events, alerts) ships first; enforcement is
added per pillar only after it has been tested on real Windows hosts.

## 2. Current state (honest)

| Area | State |
| --- | --- |
| Pillar CLIs (cyberwall, cyberdefender, cyberedr, cybersiem, cyberintel, cyberdns, cyberid, cybermesh, cyberztna) | **Exists**, single-host, mostly Windows. See README status table. |
| `aegisd` daemon | **Exists** as a foreground process with local IPC (`ping`, `status`). Not a service. |
| Signed posture tokens | **Exists** (Ed25519, per-host key, software storage). |
| Fleet server, enrollment, mTLS | **Not built.** |
| Signed policy, M-of-N approvals | **Not built.** No policy engine exists. |
| Hash-chained audit log | **Not built.** Event store is plain JSONL. |
| CI, signed releases, SBOM | **Not built** (CI in progress, `ci/baseline`). |
| TPM key storage | **Not built.** |
| Packet driver | Port only (`PacketBackend`, `NoDriver`). |

## 3. Security principles

1. **No single point of trust.** A compromised server can observe and deny
   service, but it cannot make agents run anything an admin quorum did not sign.
2. **Zero-trust agents.** One-time enrollment token → CSR → short-lived client
   certificate bound to a hardware key (TPM on Windows; software keystore is a
   clearly marked fallback). All agent↔server traffic is mutual TLS.
3. **Signed policy.** Agents apply only policy documents signed by admin keys
   that live offline or in hardware tokens. The agent pins the admin public
   keys at enrollment. Risky actions (isolate host, run script, uninstall,
   change pinned keys) require **M-of-N** admin signatures.
4. **Small, sandboxed agent.** Minimal Rust service, least privilege per
   pillar, **no remote shell by default**, deny-first command allowlist.
5. **Signed updates with rollback.** Agents verify release signatures and
   keep the previous version to roll back to.
6. **Offline grace, not a kill switch.** If the server is unreachable, agents
   keep enforcing the last valid signed policy for a bounded grace period and
   keep logging locally. No remote "disable" capability exists.
7. **Tamper-evident audit.** Every admin action and agent event goes into a
   hash-chained log; chain heads are periodically signed and replicated to
   agents and an optional external witness.
8. **Supply chain.** Reproducible builds, signed releases, SBOM, `cargo deny`
   / `cargo audit`, fuzzing of parsers in CI, external audit before 1.0.
9. **Observation before control.** Read-only features first; each enforcement
   feature has a per-pillar opt-in and Windows test evidence before release.

## 4. Threat model

### 4.1 Assets
- Admin signing keys (policy, risky-action approvals, release signing).
- Fleet CA private key (issues agent certs).
- Agent private keys and certificates.
- Policy documents and their signatures.
- Telemetry: inventory, posture, events (may contain usernames, hostnames, process names).
- Audit log integrity.
- Agent binaries and update channel.
- Endpoint availability (an agent must not brick or isolate hosts by mistake).

### 4.2 Adversaries
| ID | Adversary | Capability assumed |
| --- | --- | --- |
| A1 | Network attacker | Full MITM between agent and server. |
| A2 | Compromised fleet server | Root on the server, its DB and the online CA key. |
| A3 | Single rogue or phished admin | One admin's credentials and signing key. |
| A4 | Compromised endpoint | Admin/SYSTEM on one enrolled host. |
| A5 | Supply-chain attacker | Tampers with a dependency, CI, or release artifacts. |
| A6 | Insider with DB read access | Reads stored telemetry. |

Out of scope for now: kernel-level rootkits on the endpoint before Aegis
installs, physical attacks on TPMs, compromise of a quorum (M) of admins.

### 4.3 Trust boundaries
1. Agent process ↔ local OS (privileged boundary on the endpoint).
2. Agent ↔ fleet server (network; mTLS).
3. Fleet server ↔ admin console/CLI (network; admin auth).
4. Admin offline signing device ↔ everything else (air gap / hardware token).
5. Build/CI ↔ release artifacts ↔ agents (update channel).
6. `aegisd` ↔ local clients (`aegis`, GUI) over named pipe / Unix socket.

### 4.4 STRIDE table
| Threat | Example | Primary mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing an agent | Attacker enrolls a fake host | One-time, short-TTL enrollment tokens; hardware-bound keys; admin approval of new enrollments (optional) | Stolen unused token within its TTL |
| **S**poofing the server | A1 impersonates server | Agent pins fleet CA at enrollment; mTLS | Pinned CA compromise (A2) → see policy signing |
| **S**poofing an admin | A3 pushes policy | Policy needs admin signature; risky actions need M-of-N | A3 can push low-risk policy within their role |
| **T**ampering with policy | A2 edits policy in DB | Agents verify admin signatures against pinned keys | None if keys stay offline |
| **T**ampering with telemetry | A4 forges events | Events signed by agent key; anomaly checks server-side | A4 can lie about its own host |
| **T**ampering with audit log | A2 deletes entries | Hash chain + signed heads replicated to agents/witness | Truncation of entries newer than last replicated head |
| **R**epudiation | Admin denies an action | Every action signed and chained in audit log | — |
| **I**nformation disclosure | A6 reads telemetry | TLS in transit; minimize collected data; at-rest encryption (DB choice pending) | Server root (A2) can read telemetry |
| **I**nformation disclosure | Key theft from endpoint | TPM-bound keys; software fallback flagged in inventory | Software-key hosts |
| **D**enial of service | A2 stops serving | Offline grace period; local logging continues | Fleet visibility lost during outage |
| **D**enial of service | Bad policy isolates fleet | M-of-N for isolation; staged rollout; local break-glass documented | Quorum mistake |
| **E**levation of privilege | Remote code exec via agent | No remote shell; deny-first allowlist; no script execution without M-of-N | Bugs in agent parsers (fuzzing) |
| **E**levation of privilege | Malicious update | Release signature verification, rollback, reproducible builds | Release-key compromise |
| **E**levation of privilege | Local user abuses `aegisd` IPC | Pipe/socket ACLs restricted to admins; read-only methods by default | Misconfigured ACL |

## 5. Components

```
 [offline admin key(s)] --signs--> policy / approvals / releases
          |
 [admin console + CLI] --(admin auth, TLS)--> [aegis-fleet server] <--(mTLS)-- [aegisd agent] -- local IPC -- [aegis CLI / GUI]
                                                 |  CA (online, short-lived certs)          |  pillar engines (in-process)
                                                 |  store (SQLite, decision pending)        |  local hash-chained log
                                                 |  audit chain                             |  keystore (TPM / software)
```

- **aegisd (agent)** – Windows service / systemd unit. Hosts pillar engines
  in-process, local IPC with ACLs, enrollment client, heartbeat, policy
  verifier, local audit chain, update verifier.
- **aegis-fleet (server)** – enrollment endpoint, issuing CA for short-lived
  agent certs, heartbeat/telemetry ingest, policy distribution (stores signed
  blobs; cannot create valid ones), audit chain, admin API.
- **Admin tooling** – CLI that signs policy and approvals with offline/hardware
  keys; dashboard reads fleet state (observation first).
- **s2o-platform** – OS integration and `PacketBackend` port (exists).

### 5.1 Enrollment flow
1. Admin creates a one-time enrollment token (random 256-bit, TTL e.g. 24 h,
   stored hashed on the server, single use).
2. Agent generates a keypair in the keystore, builds a CSR, sends token + CSR
   over server-authenticated TLS (CA fingerprint supplied with the token).
3. Server checks token (exists, unexpired, unused), marks it used, issues a
   short-lived client cert (e.g. 24 h) with the agent ID in the SAN.
4. Agent renews over mTLS before expiry. A missed renewal window requires
   re-enrollment.

### 5.2 Policy flow
1. Admin drafts policy → canonical serialization → signed offline.
2. Risky actions collect M-of-N signatures.
3. Server stores and distributes; agent verifies signatures against pinned
   admin keys and a monotonic version number (rollback protection) before applying.

## 6. Roadmap and exit criteria

| Phase | Scope | Exit criteria |
| --- | --- | --- |
| 1 Cleanup | Fresh-clone build, honest status, real crypto, license | **Done** (PR #1) |
| 2 CI baseline | check/test/clippy/fmt on Linux + Windows, cargo-deny | Green on both OSes; clippy `-D warnings`; deny passes |
| 3 Enrollment + mTLS | `aegis-fleet` crate, token/CSR/short-lived certs, heartbeat | Tests: happy path, replayed token, expired cert, wrong CA; keystore trait with software impl |
| 4 Signed policy + audit | Policy format, M-of-N, hash-chained log | Agent rejects unsigned/old/under-quorum policy in tests; chain verification tool |
| 5 Agent as a service | Windows service + systemd, IPC ACLs, updates with rollback | Install/uninstall tested on Windows 10/11 VMs; signed update + rollback demo |
| 6 Fleet observation | Inventory, posture, events, alerts in dashboard | Read-only fleet view with ≥3 real Windows agents |
| 7 Enforcement | Per-pillar enforcement, ZTNA proxy, packet driver | Each pillar has Windows test evidence and opt-in; external review |
| 8 Release hardening | Reproducible builds, signed releases, SBOM, fuzzing, external audit | Independent audit report; reproducible build verified |

## 7. Open decisions
Tracked in PR discussions: deployment model (self-hosted vs SaaS), server
database beyond embedded SQLite, code-signing certificates and hosting costs,
TPM requirement vs. software fallback policy.
