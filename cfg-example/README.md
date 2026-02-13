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

- **mtu** (optional): MTU. IPv4 default 1444, IPv6 default 1424.
- **channel_limit** (optional): Queue size for packets forwarded from TUN to server; packets are dropped when exceeded. Default 100.
- **api_addr** (optional): API listen address. Default `127.0.0.1:3030`.
- **tcp_heartbeat_interval_secs** (optional): TCP heartbeat interval in seconds. Default 5.
- **udp_heartbeat_interval_secs** (optional): UDP heartbeat interval in seconds. Default 5.
- **tcp_heartbeat_continuous_loss** (optional): Number of consecutive TCP heartbeat losses before closing the connection. Default 5.
- **udp_heartbeat_continuous_loss** (optional): Number of consecutive UDP heartbeat losses before marking the peer as unavailable. Default 5.
- **udp_heartbeat_continuous_recv** (optional): Number of consecutive UDP heartbeat receives before marking the peer as available again. Default 3.
- **reconnect_interval_secs** (optional): TCP reconnect interval in seconds. Default 3.
- **udp_socket_recv_buffer_size** (optional): UDP socket receive buffer size. Default is system default.
- **udp_socket_send_buffer_size** (optional): UDP socket send buffer size. Default is system default.
- **external_routing_table** (optional): External routing table. Path is a dynamic library in the same directory as the binary: `fubukiextrt` (Windows) or `libfubukiextrt` (Unix). [Implementation](https://github.com/xutianyi1999/fubuki/blob/master/src/routing_table/external.rs)
- **allow_packet_forward** (optional): Allow forwarding packets whose destination is not this node. Default true.
- **allow_packet_not_in_rules_send_to_kernel** (optional): Allow packets that do not match routing rules to be sent to the kernel. Default false.
- **enable_hook** (optional): External hook. Path is a dynamic library in the same directory: `fubukihook` (Windows) or `libfubukhook` (Unix). [Implementation](https://github.com/xutianyi1999/fubuki/blob/master/src/common/hook.rs)
- **socket_bind_device** (optional): Bind the socket to a specific network interface for sending (e.g. `eth0` on Linux, or adapter names like `WLAN`, `Ethernet` on Windows).
- **cross_nat** (optional): Use an alternative NAT stack when the system NAT is unavailable; only takes effect when `allowed_ips` is set. Default false.
- **groups**: List of groups (virtual networks) this node joins.
  - **node_name** (optional): Node name. Default is the hostname.
  - **server_addr**: Server address for discovery and relay (`IP:PORT`).
  - **tun_addr** (optional): This node’s virtual IP and netmask. If omitted, assigned from the pool.
    - **ip**: Virtual IP address.
    - **netmask**: Subnet mask.
  - **key** (optional): Pre-shared key. Omit to disable encryption.
  - **mode** (optional): Transport mode. Default: P2P over UDP; relay prefers UDP, fallback TCP.
    - **p2p**: Protocols for direct links. Only UDP is supported.
    - **relay**: Protocols for relay. UDP and TCP supported.
  - **specify_mode** (optional): Override transport mode for traffic to specific peers (by virtual IP). Only affects upload from this node to the given peer; some limitations apply (e.g. if `mode` does not set p2p, enabling p2p in specify_mode may not take effect).
  - **lan_ip_addr** (optional): LAN address used for discovery. Default is chosen from the local routing table; can be set manually.
  - **node_binding** (optional): Bind address for the node’s UDP socket. Default `0.0.0.0:0` or `[::]:0`.
  - **allowed_ips** (optional): CIDR list of destinations that other nodes are allowed to reach via this node (relay).
  - **ips** (optional): Map destination CIDRs to a relay node (virtual IP). Example: send traffic to `192.168.201.0/24` via node `10.0.0.2`.
  - **auto_route_selection** (optional): When P2P to a peer is not possible, automatically select an intermediate node for relay. When multiple hops may be involved, this should be enabled on all nodes. Default false.
  - **use_kcp_session** (optional): Use KCP instead of TCP for session keepalive (useful when TCP is impaired). Default false.
- **features** (optional): Feature flags.
  - **disable_api_server**: Disable the API server. Default false.
  - **disable_hosts_operation**: Disable hosts file updates. Default false.
  - **disable_signal_handling**: Disable signal handling. Default false.
  - **disable_route_operation**: Disable route table operations. Default false.

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

- **channel_limit** (optional): Relay queue size; packets dropped when exceeded. Default 100.
- **api_addr** (optional): API listen address. Default `127.0.0.1:3031`.
- **tcp_heartbeat_interval_secs** (optional): TCP heartbeat interval in seconds. Default 5.
- **tcp_heartbeat_continuous_loss** (optional): Consecutive TCP heartbeat losses before closing the connection. Default 5.
- **udp_heartbeat_interval_secs** (optional): UDP heartbeat interval in seconds. Default 5.
- **udp_heartbeat_continuous_loss** (optional): Consecutive UDP heartbeat losses before marking peer unavailable. Default 5.
- **udp_heartbeat_continuous_recv** (optional): Consecutive UDP heartbeat receives before marking peer available. Default 3.
- **groups**: List of groups (virtual networks).
  - **name**: Group name.
  - **listen_addr**: Listen address (`IP:PORT`).
  - **key** (optional): Pre-shared key. Omit to disable encryption.
  - **address_range**: Virtual subnet (e.g. `10.0.0.0/24`).
  - **flow_control_rules** (optional): Relay traffic limits per destination (downstream only). Format: `["destination_cidr", "per-node rate"]` (e.g. `"10Mib"`).
  - **allow_udp_relay** (optional): Allow UDP relay. Default true.
  - **allow_tcp_relay** (optional): Allow TCP relay. Default true.
