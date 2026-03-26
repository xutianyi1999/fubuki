# Fubuki

[中文](README.zh-CN.md) | English

[![Release](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml/badge.svg)](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml)

Fubuki is a **decentralized mesh VPN** for **Windows, Linux, and macOS**. Peers share a **PSK** and **bootstrap** UDP endpoints, sync a small directory over the wire (see `doc/`), and forward IPv4 inside the virtual subnet through a **TUN** device. There is **no central server process**.

**Typical uses:** remote access, cross-site LAN, games or tools that expect one flat subnet.

### Community

- **[Fubukidaze](https://github.com/darkokoa/Fubukidaze)** targets older coordinator-based Fubuki releases; it is not aligned with this tree.

---

## Documentation

- [`doc/decentralized-architecture.md`](./doc/decentralized-architecture.md) — protocol spec  
- [`doc/maturity-roadmap.md`](./doc/maturity-roadmap.md) — engineering maturity plan (Docker mesh → full CI)  
- [`doc/README.md`](./doc/README.md) — index  
- [`cfg-example/`](./cfg-example/) — sample `dc.json` files  
- [`docker/mesh/README.md`](./docker/mesh/README.md) — Docker multi-node E2E (`./scripts/docker-mesh-test.sh`)  

---

## Quick start

1. Copy and edit [`cfg-example/dc-alice.json`](./cfg-example/dc-alice.json) (and a second peer) so `bootstrap` points at the other machine’s **IP:UDP port**, `psk` and `network_id` match, and `virtual_addr` / `listen_udp` differ per host.  
2. Run as **Administrator** (Windows) or **root** (Linux/macOS):

```bash
cargo +nightly run --release -- daemon -c cfg-example/dc-alice.json
# or after install:
fubuki daemon -c ./dc.json
```

3. Ping the other peer’s **virtual IP** once both sides are up.

---

## Prerequisites

| Platform | Notes |
|----------|--------|
| **Windows** | Administrator; [Wintun](https://www.wintun.net) DLL next to `fubuki.exe` (or on PATH / System32). |
| **Linux** | Root (or equivalent); TUN enabled in the kernel. |
| **macOS** | Root; TUN available. |

---

## CLI

```bash
fubuki daemon -c /path/to/dc.json   # start VPN (alias: start)
fubuki update                       # self-update from GitHub releases
```

---

## Build

Requires **Rust nightly** and (on Windows) **MSVC**.

```bash
cargo +nightly build --release
```

Default features include **mimalloc**. Disable with `cargo build --release --no-default-features` if needed.

---

## Cargo features

| Feature | Description |
|---------|-------------|
| `mimalloc` (default) | Global allocator. |
