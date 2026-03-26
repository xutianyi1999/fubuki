# Fubuki

[English](README.md) | 中文

[![Release](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml/badge.svg)](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml)

Fubuki 是面向 **Windows、Linux、macOS** 的**去中心化网状 VPN**：对等方使用 **PSK** 与 **bootstrap** UDP 地址同步目录（见 `doc/`），在 **TUN** 上转发虚拟子网内的 IPv4。**无独立协调进程**。

**典型用途：** 远程访问、跨站点虚拟局域网、依赖单一子网的游戏或工具。

### 社区

- **[Fubukidaze](https://github.com/darkokoa/Fubukidaze)** 面向旧版带协调端的 Fubuki，与本仓库当前架构不一致。

---

## 文档

- [`doc/decentralized-architecture.md`](./doc/decentralized-architecture.md) — 协议规格  
- [`doc/maturity-roadmap.md`](./doc/maturity-roadmap.md) — 工程成熟化路线图（Docker mesh 与 CI）  
- [`doc/README.md`](./doc/README.md) — 索引  
- [`cfg-example/`](./cfg-example/) — `dc.json` 示例  
- [`docker/mesh/README.md`](./docker/mesh/README.md) — Docker 多节点端到端测试（`./scripts/docker-mesh-test.sh`）  

---

## 快速开始

1. 复制并修改 [`cfg-example/dc-alice.json`](./cfg-example/dc-alice.json)（及第二台配置）：`bootstrap` 填对端 **IP:端口**，`psk` / `network_id` 一致，各机 `virtual_addr`、`listen_udp` 不同。  
2. **Windows 管理员** 或 **Linux/macOS root** 运行：

```bash
cargo +nightly run --release -- daemon -c cfg-example/dc-alice.json
# 安装后：
fubuki daemon -c ./dc.json
```

3. 双方启动后 **ping 对端虚拟 IP**。

---

## 环境要求

| 平台 | 说明 |
|------|------|
| **Windows** | 管理员；[Wintun](https://www.wintun.net) DLL 与 `fubuki.exe` 同目录或可用路径。 |
| **Linux** | root（或等效）；内核支持 TUN。 |
| **macOS** | root；支持 TUN。 |

---

## 命令行

```bash
fubuki daemon -c /path/to/dc.json   # 启动（别名：start）
fubuki update                       # 从 GitHub Release 自更新
```

---

## 构建

需要 **Rust nightly**；Windows 需 **MSVC**。

```bash
cargo +nightly build --release
```

默认启用 **mimalloc**；若需关闭：`cargo build --release --no-default-features`。

---

## Cargo 特性

| 特性 | 说明 |
|------|------|
| `mimalloc`（默认） | 全局分配器。 |
