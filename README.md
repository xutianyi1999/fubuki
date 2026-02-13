# Fubuki

[![Release](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml/badge.svg)](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml)

<!-- Keep these links. Translations will automatically update with the README. -->
[Deutsch](https://zdoc.app/de/xutianyi1999/fubuki) |
[English](https://zdoc.app/en/xutianyi1999/fubuki) |
[Español](https://zdoc.app/es/xutianyi1999/fubuki) |
[Français](https://zdoc.app/fr/xutianyi1999/fubuki) |
[日本語](https://zdoc.app/ja/xutianyi1999/fubuki) |
[한국어](https://zdoc.app/ko/xutianyi1999/fubuki) |
[Português](https://zdoc.app/pt/xutianyi1999/fubuki) |
[Русский](https://zdoc.app/ru/xutianyi1999/fubuki) |
[中文](https://zdoc.app/zh/xutianyi1999/fubuki)

Fubuki is a **mesh VPN**: it connects machines in different networks (home, office, cloud) into one virtual network. Each machine runs a **node** and gets a stable **virtual IP**. Nodes discover each other and connect via a central **server**; when possible they talk directly (P2P), otherwise traffic is relayed through the server.

**Use cases:** remote access to home/office devices, linking servers across regions, gaming or tools that assume a single LAN.

---

## Table of contents

- [Quick start](#quick-start)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Running server and nodes](#running-server-and-nodes)
- [Using the network](#using-the-network)
- [Web UI and TUI](#web-ui-and-tui)
- [Build from source](#build-from-source)
- [Features](#features)

---

## Quick start

1. **Prepare**  
   - One machine with a **public IP** (or port forwarding) to run the **server**.  
   - One or more machines that will join the mesh as **nodes**.

2. **Create server config** `server.json`:
   ```json
   {
     "groups": [{
       "name": "mygroup",
       "key": "your-secret-key",
       "listen_addr": "0.0.0.0:12345",
       "address_range": "10.0.0.0/24"
     }]
   }
   ```

3. **Start the server** (on the machine with public IP):
   ```bash
   fubuki server daemon ./server.json
   ```

4. **Create node config** `node.json` on each machine that should join (replace `SERVER_IP` with the server’s public IP):
   ```json
   {
     "groups": [{
       "node_name": "alice",
       "server_addr": "SERVER_IP:12345",
       "key": "your-secret-key"
     }]
   }
   ```

5. **Start each node** (as root/admin if required by your OS):
   ```bash
   fubuki node daemon ./node.json
   ```

6. **Test:** from one node, ping another by name or by virtual IP:
   ```bash
   ping bob.mygroup
   # or use the virtual IP shown in logs / Web UI
   ```

The **key** and **group name** must match between server and nodes; **node_name** must be unique per group.

---

## Prerequisites

| Platform | Notes |
|----------|--------|
| **Windows** | Run as **Administrator**. Put [wintun](https://www.wintun.net) DLL next to `fubuki.exe` or in System32. Windows 7 needs [KB3063858](https://www.microsoft.com/en-us/download/details.aspx?id=47409) and [KB4474419](https://www.catalog.update.microsoft.com/search.aspx?q=kb4474419). |
| **Linux**  | Run as **root** (or equivalent). Kernel must support **TUN**. |
| **macOS**  | Run as **root**. Kernel must support **TUN**. |

**Server:** must be reachable from all nodes (open the `listen_addr` port on the firewall and/or router).

---

## Configuration

All options are in JSON config files passed to `fubuki server daemon <path>` or `fubuki node daemon <path>`.

**For complete and advanced examples** (all supported fields, multiple groups, optional tuning), see the **[cfg-example](cfg-example/)** directory ([GitHub](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)).

### Server config

| Field | Required | Description |
|-------|----------|-------------|
| **groups** | Yes | List of groups. Each group is one virtual network. |
| **groups[].name** | Yes | Group name (e.g. `mygroup`). Nodes use this to join. |
| **groups[].key** | No | Pre-shared key. Omit for no encryption; set the same on nodes to authenticate. |
| **groups[].listen_addr** | Yes | `IP:PORT` the server listens on (e.g. `0.0.0.0:12345`). Use a public IP or `0.0.0.0`. |
| **groups[].address_range** | Yes | Virtual subnet for this group (e.g. `10.0.0.0/24`). |
| **api_addr** | No | HTTP API address (default `127.0.0.1:3031`). Used for Web UI / status. |
| **tcp_heartbeat_interval_secs** | No | Default 5. |
| **udp_heartbeat_interval_secs** | No | Default 5. |

Example with two groups:

```json
{
  "groups": [
    {
      "name": "home",
      "key": "secret1",
      "listen_addr": "0.0.0.0:12345",
      "address_range": "10.0.0.0/24"
    },
    {
      "name": "office",
      "key": "secret2",
      "listen_addr": "0.0.0.0:12346",
      "address_range": "10.0.1.0/24"
    }
  ]
}
```

### Node config

| Field | Required | Description |
|-------|----------|-------------|
| **groups** | Yes | List of groups this node joins (can join multiple). |
| **groups[].node_name** | Yes | Unique name in that group (e.g. `alice`, `laptop`). |
| **groups[].server_addr** | Yes | Server address: `IP:PORT` (must match server’s `listen_addr`). |
| **groups[].key** | No | Pre-shared key; must match the server group’s `key`. |
| **api_addr** | No | HTTP API address (default `127.0.0.1:3030`). Web UI / TUI use this. |

Example (one node, one group):

```json
{
  "groups": [{
    "node_name": "alice",
    "server_addr": "203.0.113.10:12345",
    "key": "secret1"
  ]
}
```

Example (one node, two groups):

```json
{
  "groups": [
    {
      "node_name": "alice",
      "server_addr": "203.0.113.10:12345",
      "key": "secret1"
    },
    {
      "node_name": "alice",
      "server_addr": "203.0.113.10:12346",
      "key": "secret2"
    }
  ]
}
```

---

## Running server and nodes

- **Server** (one per deployment, on a machine reachable by all nodes):
  ```bash
  fubuki server daemon /path/to/server.json
  ```

- **Node** (on each machine that should be in the mesh):
  ```bash
  fubuki node daemon /path/to/node.json
  ```

Use the same **group name** and **key** on server and nodes. Each node’s **node_name** must be unique within that group. You can run multiple nodes on the same machine with different configs (different `node_name` and/or config file).

---

## Using the network

- **By hostname:** `ping <node_name>.<group_name>` (e.g. `ping bob.mygroup`). Fubuki updates the hosts file (or you can resolve manually) so that name points to the node’s virtual IP.
- **By virtual IP:** each node gets an IP from the group’s `address_range` (e.g. `10.0.0.2`). Use this IP like any other: SSH, HTTP, game servers, etc.
- **Routing:** ensure your OS routes traffic for the group’s `address_range` via the TUN device Fubuki creates (Fubuki typically sets this up for you on supported platforms).

---

## Web UI and TUI

- **Web UI** (build with `--features web`): While the node or server is running, open `http://API_ADDR` in a browser. Defaults: node `http://127.0.0.1:3030`, server `http://127.0.0.1:3031`. The dashboard shows groups, nodes, virtual IPs, latency, and loss.
- **TUI** (terminal UI): Run `fubuki node info` or `fubuki server info` to open the status TUI. Use `--api` if the API is not on the default address:
  ```bash
  fubuki node info                    # default: 127.0.0.1:3030
  fubuki node info --api 192.168.1.5:3030
  fubuki server info                  # default: 127.0.0.1:3031
  ```

Set **api_addr** in the server or node config to change where the API (and Web UI) listens.

---

## Build from source

- **Rust:** nightly toolchain.  
- **Windows:** MSVC toolchain.

```bash
cargo +nightly build --release
```

**With Web UI** (bundled dashboard):

```bash
cd fubuki-webui && npm install && npm run build && cd ..
cargo +nightly build --release --features "web"
```

**With desktop GUI:**

```bash
cargo +nightly build --release --features "gui"
```

**Android (FFI library):**

```bash
export RUSTUP_TOOLCHAIN=nightly
cargo install cross --git https://github.com/cross-rs/cross
cross build --lib --release --no-default-features --features "ffi-export" --target aarch64-linux-android
```

---

## Features

| Feature | Cargo flag | Description |
|---------|------------|-------------|
| mimalloc | default | Alternative allocator. |
| web | `--features web` | Embed and serve Web UI from the API. |
| gui | `--features gui` | Desktop GUI (klask). |
| cross-nat | `--features cross-nat` | netstack-lwip for cross-NAT. |
| ffi-export | `--features ffi-export` | FFI for use as a library (e.g. Android). |

