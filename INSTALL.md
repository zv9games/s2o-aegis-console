# Installing S2O Aegis (self-hosted fleet)

Status: **pre-release / for testing**. Read "What works / what doesn't yet"
before you deploy anything.

You run everything yourself. There is no cloud service. The pieces are:

| Binary | Runs on | Purpose |
|---|---|---|
| `aegis-fleet` | your server (Linux recommended) | CA, enrollment, mTLS heartbeat, policy distribution, audit log |
| `aegisd` | each endpoint (Windows / Linux) | agent: enroll, renew, heartbeat, verify + apply signed policy |
| `aegis-policy` | **admin workstations (not the server)** | admin key generation, create/approve/verify policy bundles |
| `aegis-audit` | anywhere | verify the server's hash-chained audit log |
| `aegis` | operator machine | local status CLI |

## 0. Verify your download

Every archive, binary, the SBOM and `SHA256SUMS` carry a GitHub build
provenance attestation (keyless Sigstore, free). Install the GitHub CLI, then:

```sh
sha256sum -c SHA256SUMS --ignore-missing       # Windows: Get-FileHash
gh attestation verify s2o-aegis-v0.1.0-x86_64-pc-windows-msvc.zip -R zv9games/s2o-aegis-console
gh attestation verify aegisd.exe -R zv9games/s2o-aegis-console   # individual binaries too
```

`gh attestation verify` checks the file was built by this repository's
`release.yml` workflow from a specific commit. Do not run binaries that fail
verification. For a stricter check add
`--signer-workflow zv9games/s2o-aegis-console/.github/workflows/release.yml`.

## 1. Server setup (Linux)

```sh
sudo useradd --system --home /var/lib/aegis-fleet aegis
sudo install -m 0755 aegis-fleet aegis-audit /usr/local/bin/
sudo -u aegis aegis-fleet --dir /var/lib/aegis-fleet init --name fleet.example.lan
```

`init` prints the **CA fingerprint**. Write it down; agents need it.

### Admin keys and roster (do this OFF the server)

Each admin, on their own workstation:

```sh
aegis-policy keygen alice-1.key.json --key-id alice-1 --admin alice   # prompts for a passphrase (>= 12 chars)
```

Collect the public entries into `roster.json` (at least two different admins:
risky actions need 2 approvals):

```json
{"keys":[
  {"key_id":"alice-1","admin":"alice","public_key":"<from alice-1.key.json>"},
  {"key_id":"bob-1","admin":"bob","public_key":"<from bob-1.key.json>"}
],"risky_threshold":2}
```

Copy `roster.json` to `/var/lib/aegis-fleet/roster.json` **and** keep a copy
to hand to each agent (step 2). Private key files never go on the server.

### Run

```sh
sudo install -m 0644 packaging/systemd/aegis-fleet.service /etc/systemd/system/
# The audit head key is encrypted at rest; serve needs its passphrase:
sudo systemctl edit aegis-fleet   # add: [Service] Environment=AEGIS_AUDIT_PASSPHRASE=...  (or use systemd-creds)
sudo systemctl enable --now aegis-fleet
```

Open TCP 8443 to your agents only (LAN/VPN). Do not expose it to the internet
unless you must.

## 2. Hand-off to an endpoint (out of band)

```sh
sudo -u aegis aegis-fleet --dir /var/lib/aegis-fleet token     # one-time token, 24 h
```

Give the endpoint operator, **over a channel other than the network the agent
will use** (in person, phone, signed message):

- the token,
- the CA fingerprint,
- `ca.pem` and `roster.json` (these are public, but the fingerprint check
  protects against a swapped file).

## 3. Windows agent

Run an elevated PowerShell:

```powershell
mkdir C:\Program Files\S2O Aegis; copy aegisd.exe "C:\Program Files\S2O Aegis\"
cd "C:\Program Files\S2O Aegis"
.\aegisd.exe enroll --server fleet.example.lan:8443 --server-name fleet.example.lan `
  --ca ca.pem --ca-fingerprint <FINGERPRINT> --token <TOKEN> --roster roster.json
.\aegisd.exe agent --once          # one heartbeat to confirm
.\aegisd.exe service install       # S2OAegisAgent, LocalSystem, auto-start
sc.exe start S2OAegisAgent
```

State lives in `C:\ProgramData\S2O\Aegis\agent`. Uninstall:
`aegisd.exe service uninstall`.

## 4. Linux agent

```sh
sudo install -m 0755 aegisd /usr/local/bin/
sudo aegisd enroll --server fleet.example.lan:8443 --server-name fleet.example.lan \
  --ca ca.pem --ca-fingerprint <FINGERPRINT> --token <TOKEN> --roster roster.json
sudo install -m 0644 packaging/systemd/aegis-agent.service /etc/systemd/system/
sudo systemctl enable --now aegis-agent
```

## 5. Day-2

- Agents: `aegis-fleet --dir ... agents`; revoke: `aegis-fleet --dir ... revoke <id>`.
- Policy: admins build with `aegis-policy new`, each approves with
  `aegis-policy approve --key <their key file>`, then `aegis-fleet submit bundle.json`.
  Results: `aegis-fleet results`.
- Audit: `aegis-audit verify /var/lib/aegis-fleet/audit.log`.
- CA rotation (yearly): `ca-prepare-next` -> 2-approval `rotate_ca` bundle
  -> wait for agents to ack -> `reissue-server-cert --from-next` -> restart
  -> `ca-retire-old --print-body` -> 2-approval bundle -> `ca-retire-old --bundle`.

## What works / what doesn't yet

Works (tested in CI on Windows + Linux, and with real binaries on Linux):
- Enrollment with one-time tokens, CA fingerprint pinning, mTLS, 24 h certs
  auto-renewed at 12 h, 7-day offline grace, revocation.
- Signed policy bundles: M-of-N quorum, anti-rollback, agents verify against
  their own pinned roster (a compromised server cannot forge policy).
- CA rotation and retirement with dual pins.
- Hash-chained audit log with signed heads held by agents; file locking.
- Reproducible release artifacts with provenance attestations and SBOM.

Not yet / limitations:
- **Windows service has only been built in CI**, not run on a real host.
- Policy enforcement: only heartbeat interval, roster change and CA
  rotation/retire are applied. Firewall enforcement is in progress (see
  `feat/win-firewall-enforce`); isolate host, run script, uninstall are
  reported `not_implemented`.
- Agent and admin keys are **software keys** (encrypted files). TPM/FIDO2
  are planned; agents are flagged as software-key in `agents` output.
- No GUI for fleet management; no installer (MSI); no auto-update.
- Single server, SQLite; no HA.
- Binaries are not Authenticode-signed (no paid certificate); Windows
  SmartScreen will warn. Verify with `gh attestation verify` instead.
