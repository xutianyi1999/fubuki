# Fubuki 去中心化：最小 MVP 方案

> **依据**：[decentralized-architecture.md](./decentralized-architecture.md) 全量规格 + 当前仓库 `src/` 结构。  
> **目标**：用最少功能验证「无中心协调进程、PSK、虚拟 IP 互通」；实现上**新路径**与既有集中式节点协议隔离，便于迭代。

---

## 1. MVP 定义（验收标准）

同时满足即视为 MVP **完成**：

1. 至少 **2 台**对等进程，各自读独立 `dc.json`（无单独协调进程）。
2. 双方 **UDP 互通**（同一二层网段，或配置里写明对端 `ip:port`）。
3. 启动后 **60s 内** 能互相 **ping 通对方虚拟 IP**（经 TUN，ICMP）。
4. 重启其中一方，`node_id` 不变时，恢复时间与规格书 §6 的 TTL 设定一致或更短（MVP 可硬编码更 aggressive）。

**明确不做（全规格延后）**

| 延后项 | 对应规格章节 |
|--------|----------------|
| MEMBER_DIGEST / PULL / PUSH 反熵 | §6.3 |
| NAT 打洞、STUN、DATA_PROBE | §8 |
| 中继 RELAY_* | §9 |
| 邀请令牌 `k_invite` | §3.4 |
| TCP 兜底、分片大块目录 | §4 |
| 与现有 `UdpMsg`/`Register` 报文兼容 | 全规格前言 |

---

## 2. 网络与信任假设（比全规格更窄）

- **封闭域 + PSK + 无恶意**（与全规格一致）。
- **MVP 额外假设**：任意两节点之间 **已知且稳定的 UDP 三元组**（源可在 NAT 后，但需你事先把「对端看到的地址」配进 bootstrap / static_peers）。  
  换言之：MVP **不解决**「仅凭公网 bootstrap 自动跨 NAT P2P」。

---

## 3. 协议子集（对齐 §3 / §5，只实现 5 个类型）

沿用全规格 **FBDC 外层帧**（`magic`、`proto_version`、`msg_type`、`sender`、`nonce`、`ciphertext`）与 **内层** `dst: Option<NodeId>` + `payload`。

| `msg_type` | 名称 | MVP 行为 |
|------------|------|----------|
| 1 | `HELLO` | 携带本机 `listen_port`、`display_name`、`virtual_addr`、`prefix_len`、`row_version`（见下） |
| 2 | `HELLO_ACK` | 可选；MVP 可合并进 HELLO 的「互发」：收到任意合法包即更新 `direct_udp = 来源 SocketAddr` |
| 4 | `MEMBER_ANNOUNCE` | **仅广播自身一行** `DirectoryEntry`；周期如 3s |
| 9 | `PING` | 可选；无则靠 MEMBER_ANNOUNCE 刷新 TTL |
| 10 | `PONG` | 与 PING 对应用 |
| **16** | `DATA_IP`（MVP 新增编号，全规格后续可并入 §5） | 载荷：原始 IPv4 包字节（或 `dst_virtual` + IP，二选一写死） |

**目录合并**：完全采用全规格 §6.1（`row_version` 单调递增；远程更大则覆盖）。

**MVP 同步策略（替代 §6.3）**

- 维护邻居集合 `N = bootstrap ∪ 最近收包来源`（上限如 32）。
- 每 `GOSSIP_INTERVAL`（建议 3s）向 `N` 中**每一个**地址发送 `MEMBER_ANNOUNCE`（全量仅一行，体量可忽略）。
- 不设 DIGEST/PULL/PUSH；节点数上去后再切全规格反熵。

**冲突**：检测到同 `virtual_addr` 不同 `node_id` 时 **仅 `warn!` + 计数器**；数据面是否停发由实现选默认（建议：仍转发，便于调试）。

---

## 4. 密码学（与当前代码的关系）

当前 `common::cipher` 为 **XorCipher（Blake3 哈希密钥）**，用于既有集中式节点实现中的 **数据面**，**不是** AEAD，也 **不**用于 MVP 控制面。

**MVP 建议（贴合 §3）**

- 新增依赖：`hkdf` + `chacha20poly1305`（或项目接受的单一 AEAD 实现）。
- `k_control` / `k_data` 按 §3.1 从 `psk` + `network_id` 派生；**控制面与数据面密钥分离**。
- `nonce`：对 `(network_id, 本机 node_id)` 维护 **严格递增 u64** 发送计数；接收侧按 `(peer_node_id)` 记 `last_rx_nonce`，拒绝回退（全规格 §3.2）。

**实验室捷径（不推荐合并主分支）**：外层仅 CRC/Blake3 MAC + XOR，用于先打通 TUN；须在代码与文档标 `INSECURE_MVP`。

---

## 5. 数据面 `DATA_IP`（最小封装）

**推荐 MVP 载荷**：密文内为 **完整 IPv4 包**（从 TUN 读出的那一帧），不再嵌虚拟头；虚拟目的地址从 **IP 头 dst** 解析。

发送路径：

1. TUN 读出 IPv4 包 → 查目录 `dst_ip -> (peer_node_id, SocketAddr)`。
2. 若无映射 → 丢弃或走系统默认（MVP 可只支持「虚拟网段 → 全进 DC」）。
3. 用 `k_data` 封 `DATA_IP`，UDP 发到对端 `SocketAddr`。

接收路径：

1. UDP 收到 → 解 AEAD → `DATA_IP` → 写入 TUN（必要时校验源 IP 与目录一致，MVP 可省略）。

**与现有 `node/packet.rs` 的关系**：`PacketSender` 强依赖 `UdpMsg`、`ExtendedNode`、`Interface` 与协调端注册状态，**不宜**在 MVP 内硬改。应 **新建** DC 专用发送路径（见 §7），仅复用 **TUN 读写的模式**（`runtime.rs` 里 `tun.recv_packet` / 缓冲布局思路）。

---

## 6. 配置（`dc.json` MVP 形态）

在规格 §14 基础上收紧字段：

```json
{
  "network_id": "550e8400-e29b-41d4-a716-446655440000",
  "psk": "replace-with-shared-secret",
  "virtual_addr": "10.200.1.5",
  "prefix_len": 24,
  "listen_udp": 22400,
  "display_name": "alice",
  "bootstrap": ["192.168.1.20:22400", "192.168.1.21:22400"],
  "node_id_path": null
}
```

- `bootstrap`：**至少一个**可达对端；可填全网所有成员（小团队可接受）。
- `node_id_path`：`null` 时用默认路径（如用户配置目录下 `dc-{network_id}.id`）。

---

## 7. 代码落点（相对当前 `src/`）

| 模块 | 建议 | 复用现有 |
|------|------|----------|
| 入口 | `cli`：`fubuki daemon -c dc.json`；`app` 调 `dc::run` | `clap`、`anyhow` |
| 配置 | `src/dc/config.rs`：`serde` 反序列化 `dc.json` | `serde_json`、`ipnet` |
| 帧 / 消息 | `src/dc/frame.rs`、`src/dc/msg.rs`：编解码 FBDC + bincode/自定义内层 | 无（新建） |
| 密码 | `src/dc/crypto.rs`：HKDF + AEAD | 不沿用 `XorCipher` |
| 目录 | `src/dc/directory.rs`：`HashMap<NodeId, Entry>` + 合并规则 | `ahash` |
| 运行时 | `src/dc/runtime.rs`：`tokio::net::UdpSocket` + `interval` + TUN 两向任务 | **`tun::*`**、`routing_table` 可选 |
| 系统路由 | 将 `virtual_addr/prefix` 写入本机路由 | **`node/sys_route.rs`** 或同级逻辑拷贝适配 |
| 权限 | TUN 提权 | **`common/privilege.rs`** |

**已移除**：旧版 `server` / `node` 协调协议与 `common/net` 大块注册报文逻辑；当前代码路径仅为 `dc/` + TUN。

**`lib.rs`**：`mod dc` 仅在 Windows / Linux / macOS 下编译。构建：`cargo +nightly build`；运行：`fubuki daemon -c dc.json`。

---

## 8. 分阶段提交（建议 PR 粒度）

| 阶段 | 内容 | 可测 |
|------|------|------|
| **P0** | `dc.json` + UDP 收发包 + FBDC 加解密环回（无 TUN） | 两进程互发 `HELLO` 日志 |
| **P1** | `MEMBER_ANNOUNCE` + 目录表 + `GOSSIP_INTERVAL` | 一方能看到对方 `virtual_addr` |
| **P2** | TUN 起接口 + 系统路由 + `DATA_IP` 双向 | `ping` 虚拟 IP |
| **P3**（可选） | `PING`/`PONG`、`ENTRY_TTL` 剔除离线节点 | 拔网线后路由收敛 |

---

## 9. 与全规格的升级路径

1. 把 `MEMBER_ANNOUNCE`-only 换为 §6.3 反熵（DIGEST/PULL/PUSH）。
2. 引入 §8 打洞 + `DATA_PROBE`，bootstrap 只作引荐。
3. 引入 §9 中继；`DATA_IP` 发送路径增加「经 RELAY_FORWARD」分支。
4. `proto_version` 递增；保留 MVP 的 `magic` 或增加 capability 位。

---

## 10. 参考：现有代码锚点（便于检索）

- TUN 读循环与缓冲预留：`src/node/runtime.rs` 中 `tun_handler`、`UDP_MSG_HEADER_LEN` 相关布局（DC 应自定更短的前缀，不必沿用 `VirtualAddr` 前缀）。
- 虚拟地址与协议类型：`src/common/net.rs` 内 `pub mod protocol` 与 `VirtualAddr` 等（DC MVP 不直接复用其 UDP 帧，仅作对照）。
- 路由表抽象：`src/routing_table/mod.rs` — MVP 可用轻量 `HashMap<Ipv4Addr, SocketAddr>`，待多网段再接入现成表。

---

*本文档为 MVP 范围契约；实现细节变更时请同步更新本节与 [decentralized-architecture.md](./decentralized-architecture.md) 的交叉引用。*
