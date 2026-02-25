# Fubuki

[English](README.md) | 中文

[![Release](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml/badge.svg)](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml)

Fubuki 是一个**网状 VPN**：它将不同网络（家庭、办公室、云端）中的机器连接成一个虚拟网络。每台机器运行一个**节点**并拥有固定的**虚拟 IP**。节点通过中心**服务器**相互发现并建立连接；在可能的情况下直接通信（P2P），否则流量通过服务器中继。

**典型用途：** 远程访问家庭/办公室设备、跨区域互联服务器、游戏或依赖单一局域网的各类工具。

---

## 目录

- [快速开始](#快速开始)
- [前置要求](#前置要求)
- [配置](#配置)
- [运行服务器与节点](#运行服务器与节点)
- [使用网络](#使用网络)
- [Web UI 与 TUI](#web-ui-与-tui)
- [从源码构建](#从源码构建)
- [功能特性](#功能特性)

---

## 快速开始

1. **准备**
   - 一台具有**公网 IP**（或已做端口转发）的机器用于运行**服务器**。
   - 一台或多台将作为**节点**加入网状网络的机器。

2. **创建服务器配置** `server.json`：
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

3. **启动服务器**（在具有公网 IP 的机器上）：
   ```bash
   fubuki server daemon ./server.json
   ```

4. **在每个要加入的机器上创建节点配置** `node.json`（将 `SERVER_IP` 替换为服务器公网 IP）：
   ```json
   {
     "groups": [{
       "node_name": "alice",
       "server_addr": "SERVER_IP:12345",
       "key": "your-secret-key"
     }]
   }
   ```

5. **在各机器上启动节点**（若系统要求，请以 root/管理员身份运行）：
   ```bash
   fubuki node daemon ./node.json
   ```

6. **测试：** 从一台节点按名称或虚拟 IP ping 另一台：
   ```bash
   ping bob.mygroup
   # 或使用日志 / Web UI 中显示的虚拟 IP
   ```

服务器与节点间的 **key** 和 **group name** 必须一致；**node_name** 在同一组内必须唯一。

---

## 前置要求

| 平台 | 说明 |
|------|------|
| **Windows** | 以**管理员**身份运行。将 [wintun](https://www.wintun.net) DLL 放在 `fubuki.exe` 同目录或 System32 下。Windows 7 需安装 [KB3063858](https://www.microsoft.com/en-us/download/details.aspx?id=47409) 和 [KB4474419](https://www.catalog.update.microsoft.com/search.aspx?q=kb4474419)。 |
| **Linux** | 以 **root**（或等效权限）运行。内核需支持 **TUN**。 |
| **macOS** | 以 **root** 运行。内核需支持 **TUN**。 |

**服务器：** 必须能被所有节点访问（在防火墙和/或路由器上开放 `listen_addr` 端口）。

---

## 配置

所有选项均在 JSON 配置文件中，通过 `fubuki server daemon <path>` 或 `fubuki node daemon <path>` 传入。

**完整与高级示例**（所有支持的字段、多组、可选调优）请参见 **[cfg-example](cfg-example/)** 目录（[GitHub](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)）。

### 服务器配置

| 字段 | 必填 | 说明 |
|------|------|------|
| **groups** | 是 | 组列表。每组对应一个虚拟网络。 |
| **groups[].name** | 是 | 组名（如 `mygroup`）。节点通过此名称加入。 |
| **groups[].key** | 否 | 预共享密钥。不填则不加密；与节点一致时用于认证。 |
| **groups[].listen_addr** | 是 | 服务器监听地址 `IP:端口`（如 `0.0.0.0:12345`）。使用公网 IP 或 `0.0.0.0`。 |
| **groups[].address_range** | 是 | 该组的虚拟子网（如 `10.0.0.0/24`）。 |
| **api_addr** | 否 | HTTP API 地址（默认 `127.0.0.1:3031`）。供 Web UI / 状态查询使用。 |
| **tcp_heartbeat_interval_secs** | 否 | 默认 5。 |
| **udp_heartbeat_interval_secs** | 否 | 默认 5。 |

双组示例：

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

### 节点配置

| 字段 | 必填 | 说明 |
|------|------|------|
| **groups** | 是 | 本节点加入的组列表（可加入多组）。 |
| **groups[].node_name** | 是 | 在该组内的唯一名称（如 `alice`、`laptop`）。 |
| **groups[].server_addr** | 是 | 服务器地址：`IP:端口`（需与服务器的 `listen_addr` 一致）。 |
| **groups[].key** | 否 | 预共享密钥；需与服务器对应组的 `key` 一致。 |
| **api_addr** | 否 | HTTP API 地址（默认 `127.0.0.1:3030`）。Web UI / TUI 使用此地址。 |

单节点单组示例：

```json
{
  "groups": [{
    "node_name": "alice",
    "server_addr": "203.0.113.10:12345",
    "key": "secret1"
  }]
}
```

单节点双组示例：

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

## 运行服务器与节点

- **服务器**（每个部署一台，需能被所有节点访问）：
  ```bash
  fubuki server daemon /path/to/server.json
  ```

- **节点**（在每台要加入网状网络的机器上）：
  ```bash
  fubuki node daemon /path/to/node.json
  ```

服务器与节点使用相同的**组名**和 **key**。每个节点的 **node_name** 在同一组内必须唯一。同一台机器上可用不同配置运行多个节点（不同 `node_name` 和/或配置文件）。

---

## 使用网络

- **按主机名：** `ping <node_name>.<group_name>`（如 `ping bob.mygroup`）。Fubuki 会更新 hosts 文件（或你可手动解析），使该名称指向节点的虚拟 IP。
- **按虚拟 IP：** 每个节点从组的 `address_range` 获得一个 IP（如 `10.0.0.2`）。可像普通 IP 一样使用：SSH、HTTP、游戏服务器等。
- **路由：** 确保系统将组的 `address_range` 流量经由 Fubuki 创建的 TUN 设备（在支持的平台上 Fubuki 通常会代为配置）。

---

## Web UI 与 TUI

- **Web UI**（需使用 `--features web` 构建）：节点或服务器运行时，在浏览器中打开 `http://API_ADDR`。默认：节点 `http://127.0.0.1:3030`，服务器 `http://127.0.0.1:3031`。仪表盘显示组、节点、虚拟 IP、延迟与丢包。
- **TUI**（终端界面）：运行 `fubuki node info` 或 `fubuki server info` 打开状态 TUI。若 API 不在默认地址，可使用 `--api`：
  ```bash
  fubuki node info                    # 默认: 127.0.0.1:3030
  fubuki node info --api 192.168.1.5:3030
  fubuki server info                 # 默认: 127.0.0.1:3031
  ```

在服务器或节点配置中设置 **api_addr** 可修改 API（及 Web UI）的监听地址。

---

## 从源码构建

- **Rust：** nightly 工具链。
- **Windows：** MSVC 工具链。

```bash
cargo +nightly build --release
```

**带 Web UI**（内嵌仪表盘）：

```bash
cd fubuki-webui && npm install && npm run build && cd ..
cargo +nightly build --release --features "web"
```

**带桌面 GUI：**

```bash
cargo +nightly build --release --features "gui"
```

**Android（FFI 库）：**

```bash
export RUSTUP_TOOLCHAIN=nightly
cargo install cross --git https://github.com/cross-rs/cross
cross build --lib --release --no-default-features --features "ffi-export" --target aarch64-linux-android
```

---

## 功能特性

| 功能 | Cargo 特性 | 说明 |
|------|------------|------|
| mimalloc | 默认 | 替代内存分配器。 |
| web | `--features web` | 从 API 内嵌并提供 Web UI。 |
| gui | `--features gui` | 桌面 GUI（klask）。 |
| cross-nat | `--features cross-nat` | 使用 netstack-lwip 实现跨 NAT。 |
| ffi-export | `--features ffi-export` | 导出 FFI，供库使用（如 Android）。 |
