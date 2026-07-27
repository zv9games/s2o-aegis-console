# Phase 1 — Scaffolding + concrete

**Construction stage:** foundation forms for all nine rooms + structural pour.  
**Tier ceiling:** **T0 only** (portable userspace).  
**Depends on:** P0 spine (schema / store / bus / honest status).

---

## Intent

Mark all nine worlds on the slab. Pour concrete for:

1. **Suite kernel** (one front door)  
2. **Cyberwall** T0 on Windows (first real room)

Other worlds are **formed stubs**: traits, registry entries, backends that compile on every target OS and never claim ONLINE falsely.

Multi-OS **seams** are in scope. Multi-OS **parity** is not.

---

## Definition of done

| # | Outcome |
|---|---------|
| 1 | Kernel surface: config, health, policy router hooks, event spine, OS detect |
| 2 | Nine world contracts in registry (`ProductId`, health, event hooks) |
| 3 | Backend pattern: core trait + per-OS (or unsupported) impl |
| 4 | Cyberwall T0: status/enable/disable/lock real on Windows; Linux started or partial; macOS honest |
| 5 | Policy fragment v0: kernel validates; wall applies what it can |
| 6 | `aegisd status --json`: all 9 + `state` + `os` + `tier_ceiling` + `detail` |
| 7 | Build topology: `net-lib`/adapters resolve; workspace check documented per OS |
| 8 | Demo mode remains opt-in only |

---

## Non-goals

- Feature parity across Windows / Linux / macOS  
- Mesh, Gate, full EDR, SIEM EPS, IOC feeds  
- Kernel-mode drivers / WinDivert product path  
- README “all modules healthy” theater  
- egui as source of truth  

---

## Workstreams

| ID | Stream | Work | Tier |
|----|--------|------|------|
| A | Property lines | HealthState, capability fields, status schema | T0 |
| B | Kernel | Engine registry, status/start/policy hooks | T0 |
| C | Wall pour | Windows deep; Linux real/partial; macOS stub | T0 |
| D | Seams for 8 | Named stubs that compile everywhere | T0 |
| E | Topology | Fix path deps; multi-OS build notes | T0 |
| F | Proof | Smoke scripts/tests for status + wall | T0 |

---

## Suggested crate shape

```text
crates/
  s2o-schema      # + OsFamily, HealthState, PolicyDocument v0
  s2o-store
  s2o-bus
  s2o-kernel      # NEW (or extract from aegisd): registry + policy + health
  cyberwall-core / backend-windows / backend-linux / backend-macos
  (other worlds: thin contract crates or shared stub pattern — still 9 names)
  aegisd          # bin over s2o-kernel
```

Worlds 3–9 may share stub machinery **if** each remains a distinct registry product.

---

## Exit demo

1. **Windows:** `aegisd status --json` → 9 modules; cyberwall `implemented`; enable/disable verified against OS.  
2. **Linux:** workspace builds; wall `partial` or `implemented`; others honest.  
3. **macOS (if available):** builds; wall partial/unsupported with reason.  
4. **Policy:** one file applied through kernel to wall only; event written to store.

---

## After P1

- **P2 Shell** — DNS, Defender, EDR userspace; events from real actions (ceiling T0–T1).  
- See [ROADMAP.md](./ROADMAP.md).

---

## Execution log (2026-07-27)

| Item | Status |
|------|--------|
| `net-lib` junction topology | Done (local); see [BUILD.md](./BUILD.md) |
| `s2o-schema` HealthState / OsFamily / PolicyDocument | Done |
| `s2o-kernel` registry + status + policy apply | Done |
| `cyberwall-backend-macos` | Done (partial) |
| Linux backend safety pass | Done (no flush/DROP) |
| `aegisd status` / `--json` / `policy apply` | Smoke OK on Windows |
| Default `cargo check` (suite members) | Green |
| Cross-OS CI (Linux/macOS runners) | Not yet |
| README honesty rewrite | Not yet |
