# Fubuki 去中心化模式：实现规格（草案）

> **定位**：在 **封闭域 + PSK、无恶意节点、允许不稳定节点** 前提下，描述**无中心协调进程**组网的可实现细节：标识、报文封装、控制面消息、状态机、定时器、Gossip、NAT/中继与数据面。  
> **非目标**：拜占庭容错、开放互联网任意入网、与既有集中式 fubuki **协调端↔节点** 二进制报文 **字节级兼容**（实现时应使用 **新 profile / 新 magic / 新端口或新 Cargo feature** 隔离）。

---

## 0. 协议分层与版本

| 层 | 职责 |
|----|------|
| L0 | UDP（必选）承载控制面与小包数据试探；可选 TCP 流用于大目录同步或打洞失败兜底。 |
| L1 | **PSK-AEAD 帧**：认证 + 加密 + 抗重放（见 §3）。 |
| L2 | **控制面消息**（类型 + 载荷）：成员、地址声明、打洞、中继会话。 |
| L3 | **数据面帧**：虚拟 IP 载荷封装，走已建立的 P2P 或中继路径。 |

- **协议版本**：`proto_version: u16`，起始 `1`。不兼容变更递增主版本；字段扩展用可选 TLV 或 `flags`。
- **网络实例**：`network_id: [u8; 16]`（建议 UUID）；所有哈希与派生绑定 `network_id`，避免跨网复用 PSK 时误连。

---

## 1. 信任模型（不变更）

| 假设 | 含义 |
|------|------|
| 封闭组网 | 入网带外可控。 |
| PSK | 成员持有同一 `psk`（或按 `network_id` 派生会话密钥）。 |
| 无恶意 | 无伪造、投毒、拜占庭；可有错误配置。 |
| 不稳定 | 离线、抖动、分区、重复地址（误配）。 |

---

## 2. 标识符与本地持久化

### 2.1 `node_id`

- **类型**：`NodeId = [u8; 16]`，建议 **UUID v4** 存于磁盘（`~/.config/fubuki/dc-{network_id}.id` 或等价路径）。
- **语义**：逻辑节点身份；**重启不变**。与 `display_name`（人读）分离。
- **约束**：`display_name` UTF-8，长度 ≤ 64 字节，仅用于日志/UI；**路由与目录以 `node_id` 为准**。

### 2.2 虚拟地址

- `virtual_addr: Ipv4Addr`，`prefix_len: u8`（通常与组网前缀一致，如 `/24`）。
- **首版**：静态配置 + Gossip 声明；**禁止**同一 `virtual_addr` 被两个不同 `node_id` 同时声明为「活跃」（见 §7）。

### 2.3 本地核心表（内存）

```text
DirectoryEntry {
    node_id: NodeId,
    display_name: String,
    virtual_addr: Ipv4Addr,
    prefix_len: u8,
    // 可达性（多槽位，见 §8/§9）
    direct_udp: Option<SocketAddrV4>,   // 对端「认为」可收包的地址
    direct_udp_seen: Instant,
    relay_via: Option<NodeId>,          // 当前选用的中继节点
    version: u64,                       // 单调递增的「目录行版本」，见 §6
    ttl_expires: Instant,               // 未刷新则剔除
}

PeerSession {
    node_id: NodeId,
    crypto: SessionKeys,                // 由 PSK 派生的 per-peer 或 per-direction 密钥（见 §3.3）
    last_rx_nonce: u64,
    mtu: u16,
}
```

---

## 3. 密码学与报文封装

### 3.1 PSK 派生（实现必须固定标签，写入代码常量）

使用 **HKDF-SHA256**（或项目已依赖的等价 PRF）：

```text
info_network = "fubuki-dc/v1/network" || network_id
k_control    = HKDF-Expand(psk, info="control"    || info_network, L=32)
k_data       = HKDF-Expand(psk, info="data"       || info_network, L=32)
k_invite     = HKDF-Expand(psk, info="invite"     || info_network, L=32)  // 仅用于签发邀请令牌
```

- **控制面 AEAD**：`ChaCha20Poly1305` 或 `AES-256-GCM`（二选一写死；全实现统一）。
- **数据面**：可与控制面共用 `k_data`，或再 HKDF：`k_peer = HKDF-Expand(k_data, info=node_id_A || node_id_B, L=32)`（字节序与连接方向规则固定）。

### 3.2 帧格式（UDP 负载）

所有控制面 UDP 报文（除明确规定的 **明文 STUN** 外）使用同一外层：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | `magic` | 固定 `0x46 0x42 0x44 0x43`（`FBDC`）与现有 fubuki 区分 |
| 4 | 2 | `proto_version` | `1` |
| 6 | 2 | `msg_type` | 枚举 §5 |
| 8 | 16 | `sender` | `NodeId` |
| 24 | 8 | `nonce` | 严格递增；对 `(sender, receiver)` 或 `(sender, network)` 维护，防重放 |
| 32 | 2 | `payload_len` | 密文长度 |
| 34 | var | `ciphertext` | AEAD 密文，内含内层明文（见 §3.4） |

- **关联数据 AAD**：`magic || proto_version || msg_type || sender || nonce`（或含 `network_id` 的哈希），实现时**固定文档**。
- **重放窗口**：每对 peer 保留 `last_rx_nonce`，拒绝 `nonce <= last`；允许可配置 `WINDOW=32` 的乱序窗口（可选，首版可不做）。

### 3.3 内层明文（解密后）

建议统一：

| 字段 | 类型 | 说明 |
|------|------|------|
| `dst` | `Option<NodeId>` | `None` = 广播/多播给邻居；`Some` = 单播 |
| `payload` | `bytes` | 按 `msg_type` 解析 |

### 3.4 邀请令牌（带外）

二进制结构（由 `k_invite` 计算 MAC，或整体 AEAD）：

| 字段 | 说明 |
|------|------|
| `network_id` | 16 字节 |
| `issued_at` | `u64` unix sec |
| `expires_at` | `u64` |
| `allowed_prefix` | `Ipv4Net` 编码（addr + len） |
| `allowed_host_id` | 可选 `NodeId`（绑定新节点 id） |
| `mac` | 16 字节（Truncated HMAC-SHA256）或 Poly1305 tag |

验证失败 → 拒绝 `JOIN` / `CLAIM`。

---

## 4. 传输与端口

- **控制/数据 UDP 端口**：配置项 `listen_udp: u16`（默认建议与现网不同，如 `22400`）。
- **Bootstrap 连接**：向配置的 `bootstrap[]` 发送 `MEMBER_ANNOUNCE`（自身目录行）；成功后加入邻居 fan-out 集合。
- **TCP 兜底**（可选实现）：用于 `DIR_SNAPSHOT` 大块；首版可省略，用 **分片 Gossip** 代替。

---

## 5. 控制面消息类型（`msg_type`）

下列值为建议枚举（实现可用 `u16` 稀疏分配）：

| `msg_type` | 名称 | 方向 | 载荷概要 |
|------------|------|------|----------|
| 1 | *（实现未用）* | — | 保留编号空档 |
| 2 | *（实现未用）* | — | 保留编号空档 |
| 3 | `PEER_INTRO` | A→B（经第三方转发或由 bootstrap 引荐） | `target: NodeId`, `hint_addr` |
| 4 | `MEMBER_ANNOUNCE` | 广播/多播 | 完整 `DirectoryEntry` 快照单行（**当前实现**：bootstrap + 周期 gossip） |
| 5 | `MEMBER_DIGEST` | 反熵 | `version_vector: Vec<(NodeId,u64)>` 或 Bloom+版本（首版用向量） |
| 6 | `MEMBER_PULL` | 请求 | `want: Vec<NodeId>` |
| 7 | `MEMBER_PUSH` | 响应 | `entries: Vec<DirectoryEntry>` |
| 8 | `ADDR_CONFLICT` | 定向 | 两个 `NodeId` 同 `virtual_addr` 证据 |
| 9 | `PING` / 10 `PONG` | 保活 | `monotonic`, `rtt_sample` |
| 11 | `HOLE_PUNCH_REQ` | 打洞 | `session_id`, `role`, `cookie` |
| 12 | `HOLE_PUNCH_ACK` | 打洞 | 同上 |
| 13 | `RELAY_REGISTER` | 中继 | `capacity`, `token` |
| 14 | `RELAY_FORWARD` | 中继 | `inner_mac`, 内层加密数据包 |
| 15 | `DATA_PROBE` | 路径探测 | 小 payload，测量可达性 |

**本仓库实现与上表编号差异**：使用 `msg_type=8` 为 `NEIGHBOR_SYNC`（有界 reach 同步），`msg_type=16` 为 `DATA_IP`；未实现 `HELLO` / `HELLO_ACK`。

**广播语义**：`dst=None` 时，仅向 **当前 `active_neighbors` 集合** 转发（非全网泛洪），除非 `TTL` 字段递减（可选）。

---

## 6. 目录同步（Gossip / 反熵）

### 6.1 版本与合并规则

- 每个 `node_id` 维护单调 **`row_version: u64`**，本地每次 **主动变更**（地址、显示名、可达性重大变化）执行 `row_version += 1`。
- 收到远程 `DirectoryEntry`：
  - 若本地无该 `node_id` → 插入。
  - 若 `remote.version > local.version` → 覆盖。
  - 若 `remote.version == local.version` 且字段不同 → **按字典序比较 `node_id` 较小者胜出** 或 **标记 CONFLICT 上报 UI**（实现选一种写死）。
  - 若 `remote.version < local.version` → 忽略。

### 6.2 反熵周期

| 参数 | 建议初值 | 说明 |
|------|----------|------|
| `GOSSIP_INTERVAL` | 3s ± 30% jitter | 向 `k` 个邻居发 `MEMBER_DIGEST` |
| `k` | 3 | 每轮随机选邻居 |
| `ENTRY_TTL` | 120s | 未收到该 `node_id` 刷新则标记 `stale`，再 `GRACE=60s` 删除 |
| `PING_INTERVAL` | 15s | 对 `active_paths` 发 `PING` |

**邻居表**：最近成功通信的 `NodeId` 列表，上限 `MAX_NEIGHBORS=64`，LRU 驱逐。

### 6.3 伪代码（拉取补全）

```text
on_timer gossip_tick:
  digest = map(|(id, e)| (id, e.version))
  for each n in random_k_neighbors(k):
    send MEMBER_DIGEST(digest) to n

on_recv MEMBER_DIGEST(remote_digest):
  want = []
  for (id, ver) in remote_digest:
    if local[id].version < ver: want.push(id)
  if want not empty: send MEMBER_PULL(want)

on_recv MEMBER_PULL(want):
  send MEMBER_PUSH(entries for id in want)
```

---

## 7. 地址声明与冲突

### 7.1 启动序列

1. 读配置 `virtual_addr` + `psk` + `network_id` + `bootstrap`。
2. 加载/生成 `node_id`。
3. 向 bootstrap 发 `MEMBER_ANNOUNCE` → 获得至少一个邻居（收包源进入 LRU）。
4. 周期发 `MEMBER_ANNOUNCE` + 可选 `NEIGHBOR_SYNC`（自身行 / 有界 reach 表，`version` 见持久化逻辑）。
5. **冲突检测**：若收到他节点 `MEMBER_ANNOUNCE` / `MEMBER_PUSH` 中 **同 `virtual_addr` 且 `node_id` 不同`**：
   - 进入 `ConflictState`：向双方发 `ADDR_CONFLICT`，UI/日志告警。
   - **策略 A（推荐首版）**：**后启动者**停止转发数据面并退避（比较 `node_id` 字典序或启动时间戳协商字段）。
   - **策略 B**：人工修复配置后重启。

### 7.2 邀请制地址（可选）

- 新节点携带 **邀请令牌** 在首个 `MEMBER_ANNOUNCE` 或专用 `JOIN` 消息中提交。
- 令牌限定 `allowed_prefix`；节点从前缀内自选地址时，**不得**与目录中已声明冲突。

---

## 8. NAT 穿透（UDP 打洞）

### 8.1 前置

- 可选 **STUN**（与数据口独立或复用）：获取 `server_reflexive` 地址，写入 `DirectoryEntry` 辅助字段。
- 两节点 A、B 需交换 **外部端点猜测**：通过 Gossip 中的 `direct_udp`、`NEIGHBOR_SYNC`，或 `bootstrap` 路径上观测到的对端地址。

### 8.2 打洞会话

| 字段 | 说明 |
|------|------|
| `session_id` | 随机 `u64` |
| `cookie` | 随机 `u128`，防错配 |
| 角色 | `initiator` / `responder` |

**时序（同时打开）：**

1. A、B 经 Gossip 已知对方 `NodeId` 与最近 `hint` 地址。
2. A 向 `B_hint` 连续发 `N=10` 个 `HOLE_PUNCH_REQ`（间隔 20ms）；B 向 `A_hint` 同样发 `HOLE_PUNCH_ACK`（或对称 REQ）。
3. **窗口** `HOLE_PUNCH_WINDOW_MS=2000` 内，任一方收到对包 → 标记 `direct_path=Probable`，开始 `DATA_PROBE`。
4. `DATA_PROBE` 双向成功 → `direct_path=Established`，数据面优先走直连。

**失败**：超时进入 **中继选择**（§9）。

### 8.3 对称 NAT

- 若连续 `M=3` 轮打洞失败且 STUN 显示高对称性，**跳过重试**，直接选中继。

---

## 9. 中继（自愿节点）

### 9.1 注册

- 能力节点广播 `RELAY_REGISTER`（含 `capacity`, `load_epoch`）。
- 消费者维护 `relay_candidates: Vec<NodeId>`，按 **RTT 探测** 与 **当前负载**（可选字段）排序。

### 9.2 中继帧

- `RELAY_FORWARD`：**外层** AEAD 到 relay；**内层** 再 AEAD 到目标 `dst_node_id`（relay 不解析内层，仅按路由表转发）。
- **会话**：`relay_session_id`，空闲 `RELAY_IDLE_SEC=120` 释放。

### 9.3 故障转移

- 对每条路径维护 `last_ok_rx`；若 `now - last_ok_rx > PATH_DEAD_SEC=5`：
  - 直连：回到 §8 重试或切换下一候选 `hint`。
  - 中继：选下一 `relay_candidate`，重建会话。

---

## 10. 数据面

### 10.1 封装（与现有 TUN 路径对接）

在虚拟 IP 包外增加 **短头**（若与现 Fubuki 帧兼容则复用；否则新头）：

| 字段 | 说明 |
|------|------|
| `dst_virtual` | `Ipv4Addr` 目标虚拟地址 |
| `src_virtual` | `Ipv4Addr` 源 |
| `flags` | 分片、压缩预留 |
| `inner` | 原始 IP 包 |

发送路径：

1. 查 `DirectoryEntry` 得 `dst_node_id`。
2. 若存在 `direct_path=Established` → UDP 发往对端 `direct_udp`。
3. 否则若配置允许中继 → `RELAY_FORWARD`。
4. 否则 **丢弃** 并计数 `drop_no_route`。

### 10.2 广播/多播（首版）

- **建议禁用** 或仅局域网：实现成本高；文档标记为 **v2**。

---

## 11. 节点总状态机（实现清单）

```text
Boot -> Joining -> SyncingDirectory -> Ready
Ready --(addr conflict)--> Conflict -> (manual/lose) -> Ready
Ready --(all paths dead)--> Reconnecting -> Ready
```

- **`Joining`**：仅与 bootstrap 通信。
- **`SyncingDirectory`**：直到收到至少 `N=1` 条他节点条目或超时 `SYNC_TIMEOUT=30s`（仅单机则允许退化）。
- **`Ready`**：TUN 读循环 + UDP socket + 定时器驱动 Gossip/打洞。

---

## 12. 定时器与退避（汇总表）

| 名称 | 默认值 | 触发动作 |
|------|--------|----------|
| `gossip_tick` | 3s ± jitter | 反熵 |
| `entry_ttl_refresh` | 收到任意对端该 id 的合法控制包即刷新 TTL |
| `ping` | 15s | 路径保活 |
| `hole_punch_burst` | 10×20ms | 打洞 |
| `path_dead` | 5s | 切换路径 |
| `reconnect_bootstrap` | 1s → 2s → … 最大 60s 指数退避 | bootstrap 全失效 |

**抖动节点**：同一 `node_id` 若 1 分钟内 **flap > 10 次**，将其 `gossip_fanout` 临时降为 1，避免目录风暴。

---

## 13. 与当前仓库代码的映射

| 逻辑 | 位置 |
|------|------|
| FBDC 帧、HKDF/AEAD、目录、运行时 | `src/dc/` |
| TUN | `src/platform/tun/`（仅 Windows / Linux / macOS） |
| 系统路由 | `src/platform/sys_route.rs` |
| CLI | `src/cli.rs`、`src/app.rs` |
| 权限 | `src/common/privilege.rs` |

旧版 `server` / `node` / `common::net` 协调协议已从本仓库移除。

---

## 14. 配置示例（`node-dc.json` 草案）

```json
{
  "network_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "psk": "base64:....",
  "virtual_addr": "10.200.1.5",
  "prefix_len": 24,
  "listen_udp": 22400,
  "display_name": "alice-laptop",
  "bootstrap": [
    "192.168.1.10:22400",
    "vpn.example.com:22400"
  ],
  "stun_servers": ["stun.qq.com:3478", "stun.t7000.com:3478"],
  "relay": { "enable_client": true, "enable_server": false }
}
```

---

## 15. 测试与验收（实现阶段门槛）

| 用例 | 预期 |
|------|------|
| 两节点 + 同一交换机 | 仅 mDNS/广播邻居即可通 |
| 两节点 + 不同 NAT + 1 bootstrap | 打洞或中继至少一条成功 |
| 拔掉 bootstrap | 已连接集群继续 Gossip 至少 `TTL` 内可用 |
| 故意配同 IP | 冲突状态可观测，不静默丢包 |

---

## 16. 附录：与上文「粗粒度章节」的对应关系

- 原 **拓扑 4.2/4.3** → 本文 §4 + §6 +（可选）DHT 作为 **MEMBER_* 的存储后端**，接口不变。
- 原 **身份 §5** → 本文 §2 + §3。
- 原 **地址 §6** → 本文 §7。
- 原 **发现 §7** → 本文 §6。
- 原 **NAT §8** → 本文 §8。
- 原 **路由 §9** → 本文 §10。
- 原 **故障 §10** → 本文 §6 TTL、§9 故障转移、§12 退避。

---

*本文档为实现草案，落地时应将「建议初值」收敛为代码常量并配套集成测试；修订请更新本文件末尾变更说明。*
