[English](README.md) | 中文

### 去中心化配置（`dc.json`）

完整字段说明见 [`doc/decentralized-mvp.md`](../doc/decentralized-mvp.md)。

- **`dc-alice.json` / `dc-bob.json`** — 同一 `network_id` 与 `psk`；`bootstrap` 填对端**局域网 IP** 与 UDP 端口。本机联调示例使用 `127.0.0.1` 与不同 `listen_udp`。

以管理员 / root 运行：

```bash
fubuki daemon -c cfg-example/dc-alice.json
```
