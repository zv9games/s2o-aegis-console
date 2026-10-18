# lib/ — vendored WinDivert 2.2.2 (optional packet-driver port)

This folder is an unmodified copy of the upstream **WinDivert 2.2.2** release
(https://reqrypt.org/windivert.html, by basil00). It is **not used by the
default build**. Nothing in the workspace links to these files today.

| Path | What it is |
| --- | --- |
| `WinDivert.dll`, `WinDivert.lib`, `WinDivert64.sys` | Copies of the `x64/` files, kept at the top level for convenience |
| `x64/`, `x86/` | Upstream user-mode DLL/import lib, the kernel driver (`.sys`), and upstream sample tools (`netdump.exe`, `netfilter.exe`, `webfilter.exe`, `test.exe`, …) |
| `include/windivert.h` | C header for the API |
| `doc/WinDivert.html` | Upstream documentation |
| `LICENSE`, `README`, `CHANGELOG`, `VERSION` | Upstream files (LGPL-3.0 or GPL-2.0, your choice) |

## How it relates to Aegis

Packet capture goes through the `PacketBackend` trait in
`crates/s2o-platform/src/packet.rs`:

* Default build: `NoDriver` backend, capture reported as unavailable.
* `--features s2o-platform/packet-driver`: compiles the `DriverBackend` slot
  meant for WinDivert (these files) or a future CA-signed custom driver/DLL.
  **The binding is not implemented yet**; the slot returns `Unsupported`.

## Shipping notes

* WinDivert's driver is signed by its author; shipping it means shipping a
  third-party kernel driver and following its LGPL/GPL terms.
* The sample `.exe` tools are not needed by Aegis and should not go into an
  installer (`packaging/installer.iss` does not include them).
* A custom driver signed under your own EV/attestation certificate (yearly
  cost) is the intended long-term replacement; it should implement
  `PacketBackend` so callers do not change.
