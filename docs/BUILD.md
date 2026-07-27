# Build topology

## Path dependency: `s2o_net_lib`

Windows Cyberwall and several tools depend on `s2o_net_lib`.

**Expected layout:**

```text
<parent>/
  aegis-console/   # or this worktree (aegis-2)
  net-lib/         # s2o_net_lib crate (dir or junction)
```

Path deps resolve as:

| Crate | Path |
|-------|------|
| root `xallfirewall` | `../net-lib` |
| `cyberwall-backend-windows`, `cyberedr`, `cyberdefender` | `../../../net-lib` |

### Setup script (preferred)

```powershell
pwsh -File scripts/setup-net-lib.ps1
# optional override:
$env:S2O_NET_LIB = 'C:\ZV9\lines\s2o\net-lib'
pwsh -File scripts/setup-net-lib.ps1
```

The script creates a **junction** at `<repo-parent>/net-lib` pointing at a discovered or env-specified checkout. Canonical lines copy: `C:\ZV9\lines\s2o\net-lib`.

CI: check out `net-lib` as a sibling directory or run the setup script with `S2O_NET_LIB` set before `cargo check`.

## Check suite (default members)

```powershell
cargo check
cargo test -p s2o-schema -p s2o-store -p s2o-kernel
cargo build -p aegisd -p cyberwall-cli
```

Legacy egui root (`xallfirewall`) is still a workspace member but not a default member.

## Smoke

```powershell
cargo run -p aegisd -- status
cargo run -p aegisd -- status --json
cargo run -p cyberwall-cli -- status
cargo run -p aegisd -- policy example
# elevates OS firewall — use carefully:
# cargo run -p aegisd -- policy apply policies/examples/wall-enable.json
```
