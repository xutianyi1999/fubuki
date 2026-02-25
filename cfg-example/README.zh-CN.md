[English](README.md) | 中文

### node-conf.json

```json
{
  "mtu": 1444,
  "channel_limit": 100,
  "api_addr": "127.0.0.1:3030",
  "tcp_heartbeat_interval_secs": 5,
  "udp_heartbeat_interval_secs": 5,
  "tcp_heartbeat_continuous_loss": 5,
  "udp_heartbeat_continuous_loss": 5,
  "udp_heartbeat_continuous_recv": 3,
  "reconnect_interval_secs": 3,
  "udp_socket_recv_buffer_size": 8192,
  "udp_socket_send_buffer_size": 8192,
  "external_routing_table": false,
  "allow_packet_forward": true,
  "allow_packet_not_in_rules_send_to_kernel": false,
  "enable_hook": false,
  "socket_bind_device": "eth0",
  "cross_nat": false,
  "groups": [
    {
      "node_name": "t1",
      "server_addr": "192.168.1.10:12345",
      "tun_addr": {
        "ip": "10.0.0.1",
        "netmask": "255.255.255.0"
      },
      "key": "123",
      "mode": {
        "p2p": ["UDP"],
        "relay": ["UDP", "TCP"]
      },
      "specify_mode": {
        "10.0.0.2": {
          "p2p": [],
          "relay": ["UDP", "TCP"]
        }
      },
      "lan_ip_addr": "192.168.0.2",
      "node_binding": "0.0.0.0:0",
      "allowed_ips": [
        "192.168.200.0/24"
      ],
      "ips": {
        "10.0.0.2": [
          "192.168.201.0/24"
        ]
      },
      "auto_route_selection": false,
      "use_kcp_session": false
    }
  ],
  "features": {
    "disable_api_server": false,
    "disable_hosts_operation": false,
    "disable_signal_handling": false,
    "disable_route_operation": false
  }
}
```

- **mtu**（可选）：MTU。IPv4 默认 1444，IPv6 默认 1424。
- **channel_limit**（可选）：从 TUN 转发到服务器的包队列大小；超出时丢包。默认 100。
- **api_addr**（可选）：API 监听地址。默认 `127.0.0.1:3030`。
- **tcp_heartbeat_interval_secs**（可选）：TCP 心跳间隔（秒）。默认 5。
- **udp_heartbeat_interval_secs**（可选）：UDP 心跳间隔（秒）。默认 5。
- **tcp_heartbeat_continuous_loss**（可选）：连续丢失多少次 TCP 心跳后关闭连接。默认 5。
- **udp_heartbeat_continuous_loss**（可选）：连续丢失多少次 UDP 心跳后将该对端标为不可用。默认 5。
- **udp_heartbeat_continuous_recv**（可选）：连续收到多少次 UDP 心跳后将该对端标为可用。默认 3。
- **reconnect_interval_secs**（可选）：TCP 重连间隔（秒）。默认 3。
- **udp_socket_recv_buffer_size**（可选）：UDP 套接字接收缓冲区大小。默认使用系统默认值。
- **udp_socket_send_buffer_size**（可选）：UDP 套接字发送缓冲区大小。默认使用系统默认值。
- **external_routing_table**（可选）：外部路由表。路径为与可执行文件同目录下的动态库：`fubukiextrt`（Windows）或 `libfubukiextrt`（Unix）。[实现](https://github.com/xutianyi1999/fubuki/blob/master/src/routing_table/external.rs)
- **allow_packet_forward**（可选）：是否允许转发目的不是本节点的包。默认 true。
- **allow_packet_not_in_rules_send_to_kernel**（可选）：是否允许不匹配路由规则的包发往内核。默认 false。
- **enable_hook**（可选）：外部钩子。路径为同目录下的动态库：`fubukihook`（Windows）或 `libfubukhook`（Unix）。[实现](https://github.com/xutianyi1999/fubuki/blob/master/src/common/hook.rs)
- **socket_bind_device**（可选）：将套接字绑定到指定网卡发送（如 Linux 的 `eth0`，或 Windows 的适配器名如 `WLAN`、`Ethernet`）。
- **cross_nat**（可选）：在系统 NAT 不可用时使用替代 NAT 栈；仅在设置 `allowed_ips` 时生效。默认 false。
- **groups**：本节点加入的组（虚拟网络）列表。
  - **node_name**（可选）：节点名称。默认为主机名。
  - **server_addr**：用于发现与中继的服务器地址（`IP:端口`）。
  - **tun_addr**（可选）：本节点虚拟 IP 与子网掩码。不填则从地址池分配。
    - **ip**：虚拟 IP 地址。
    - **netmask**：子网掩码。
  - **key**（可选）：预共享密钥。不填则禁用加密。
  - **mode**（可选）：传输模式。默认：P2P 用 UDP；中继优先 UDP，回退 TCP。
    - **p2p**：直连使用的协议。仅支持 UDP。
    - **relay**：中继使用的协议。支持 UDP 和 TCP。
  - **specify_mode**（可选）：针对发往特定对端（按虚拟 IP）的流量覆盖传输模式。仅影响本节点到该对端的上行；存在限制（例如若 `mode` 未启用 p2p，在 specify_mode 中启用 p2p 可能不生效）。
  - **lan_ip_addr**（可选）：用于发现的局域网地址。默认从本地路由表选择；可手动指定。
  - **node_binding**（可选）：节点 UDP 套接字绑定地址。默认 `0.0.0.0:0` 或 `[::]:0`。
  - **allowed_ips**（可选）：允许其他节点经本节点（中继）访问的目的地 CIDR 列表。
  - **ips**（可选）：将目的 CIDR 映射到中继节点（虚拟 IP）。示例：经节点 `10.0.0.2` 发送到 `192.168.201.0/24` 的流量。
  - **auto_route_selection**（可选）：当无法与某对端 P2P 时，自动选择中间节点做中继。涉及多跳时应在此路径上所有节点启用。默认 false。
  - **use_kcp_session**（可选）：用 KCP 替代 TCP 做会话保活（在 TCP 不佳时有用）。默认 false。
- **features**（可选）：功能开关。
  - **disable_api_server**：禁用 API 服务。默认 false。
  - **disable_hosts_operation**：禁用 hosts 文件更新。默认 false。
  - **disable_signal_handling**：禁用信号处理。默认 false。
  - **disable_route_operation**：禁用路由表操作。默认 false。

### server-conf.json

```json
{
  "channel_limit": 100,
  "api_addr": "127.0.0.1:3031",
  "tcp_heartbeat_interval_secs": 5,
  "tcp_heartbeat_continuous_loss": 5,
  "udp_heartbeat_interval_secs": 5,
  "udp_heartbeat_continuous_loss": 5,
  "udp_heartbeat_continuous_recv": 3,
  "groups": [
    {
      "name": "group1",
      "listen_addr": "0.0.0.0:12345",
      "key": "123",
      "address_range": "10.0.0.0/24",
      "flow_control_rules": [
        ["10.0.0.0/24", "10Mib"]
      ],
      "allow_udp_relay": true,
      "allow_tcp_relay": true
    }
  ]
}
```

- **channel_limit**（可选）：中继队列大小；超出时丢包。默认 100。
- **api_addr**（可选）：API 监听地址。默认 `127.0.0.1:3031`。
- **tcp_heartbeat_interval_secs**（可选）：TCP 心跳间隔（秒）。默认 5。
- **tcp_heartbeat_continuous_loss**（可选）：连续丢失多少次 TCP 心跳后关闭连接。默认 5。
- **udp_heartbeat_interval_secs**（可选）：UDP 心跳间隔（秒）。默认 5。
- **udp_heartbeat_continuous_loss**（可选）：连续丢失多少次 UDP 心跳后将对端标为不可用。默认 5。
- **udp_heartbeat_continuous_recv**（可选）：连续收到多少次 UDP 心跳后将对端标为可用。默认 3。
- **groups**：组（虚拟网络）列表。
  - **name**：组名。
  - **listen_addr**：监听地址（`IP:端口`）。
  - **key**（可选）：预共享密钥。不填则禁用加密。
  - **address_range**：虚拟子网（如 `10.0.0.0/24`）。
  - **flow_control_rules**（可选）：按目的地的中继流量限制（仅下行）。格式：`["目的_cidr", "每节点速率"]`（如 `"10Mib"`）。
  - **allow_udp_relay**（可选）：是否允许 UDP 中继。默认 true。
  - **allow_tcp_relay**（可选）：是否允许 TCP 中继。默认 true。
