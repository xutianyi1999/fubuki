### node-conf.json

```json
{
  "mtu": 1446,
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
  "groups": [
    {
      "node_name": "t1",
      "server_addr": "192.168.1.10:12345",
      "tun_addr": {
        "ip": "10.0.0.1",
        "netmask": "255.255.255.0"
      },
      "key": "123",
      "enable_key_rotation": false,
      "mode": {
        "p2p": [
          "UDP"
        ],
        "relay": [
          "UDP",
          "TCP"
        ]
      },
      "specify_mode": {
        "10.0.0.2": {
          "p2p": [],
          "relay": ["UDP", "TCP"]
        }
      },
      "lan_ip_addr": "192.168.0.2",
      "allowed_ips": [
        "192.168.200.0/24"
      ],
      "ips": {
        "10.0.0.2": [
          "192.168.201.0/24"
        ]
      }
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

- mtu(可选): MTU，IPV4默认1446，IPV6默认1426
- channel_limit(可选): 从TUN转发至server的队列大小，超过limit丢包，默认100
- api_addr(可选): API监听地址，默认`127.0.0.1:3030`
- tcp_heartbeat_interval_secs(可选): TCP 心跳包发送间隔，默认5秒
- udp_heartbeat_interval_secs(可选): UDP 心跳包发送间隔，默认5秒
- tcp_heartbeat_continuous_loss(可选): TCP 心跳包连续丢失次数，等于或超过次数则中断连接，默认5
- udp_heartbeat_continuous_loss(可选): UDP 心跳包连续丢失次数，等于或超过次数则变更目标为不可用，默认5
- udp_heartbeat_continuous_recv(可选): UDP 心跳包连续接收次数，等于或超过次数则恢复目标为可用，默认3
- reconnect_interval_secs(可选): TCP 重连间隔，默认3秒
- udp_socket_recv_buffer_size(可选): UDP socket 接收缓冲区，默认为系统默认值
- udp_socket_send_buffer_size(可选): UDP socket 发送缓冲区，默认为系统默认值
- groups: 配置多组网段
    - node_name(可选): 节点名称, 默认主机名
    - server_addr: 该网段发现服务器与中转服务器地址
    - tun_addr(可选): 本地节点的IP地址与掩码，默认从地址池获取
        - ip: 节点IP地址
        - netmask: 子网掩码
    - key(可选): 预共享密钥, 不设置则不开启加密
    - enable_key_rotation(可选): 基于时间的密钥轮换，要求节点之间的系统时间尽可能的同步, 默认为false
    - mode(可选): 数据传输方式，默认直连为UDP，中转优先使用UDP，备选TCP
        - p2p: 直连的协议，目前仅支持UDP
        - relay: 中转的协议，支持UDP与TCP
    - specify_mode(可选): 指定节点的数据传输方式, 仅覆盖当前节点到目标节点的数据发送方式
    - lan_ip_addr(可选): 默认通过本地路由表选择, 可以手动指定LAN地址
    - allowed_ips(可选): 允许其余节点通过本地节点转至发目的网段
    - ips(可选): 发送至目标网段的数据通过另一个节点去转发，例如通过'10.0.0.2'节点发送至目标'192.168.201.0/24'网段的机器
- features: 功能开关（可选）
    - disable\_api\_server: 禁用api server，默认为false
    - disable\_hosts\_operation: 禁用hosts文件操作，默认为false
    - disable\_signal\_handling: 禁用信号事件处理，默认为false
    - disable\_route\_operation: 禁用路由操作，默认为false

### server-config.json

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
      "enable_key_rotation": false,
      "address_range": "10.0.0.0/24"
    }
  ]
}
```

- channel_limit(可选): 转发队列大小，超过limit丢包，默认100
- api_addr(可选): API监听地址，默认`127.0.0.1:3031`
- tcp_heartbeat_interval_secs(可选): TCP 心跳包发送间隔，默认5秒
- tcp_heartbeat_continuous_loss(可选): TCP 心跳包连续丢失次数，等于或超过次数则中断连接，默认5
- udp_heartbeat_interval_secs(可选): UDP 心跳包发送间隔，默认5秒
- udp_heartbeat_continuous_loss(可选): UDP 心跳包连续丢失次数，等于或超过次数则变更目标为不可用，默认5
- udp_heartbeat_continuous_recv(可选): UDP 心跳包连续接收次数，等于或超过次数则恢复目标为可用，默认3
- groups 配置多组网段
    - name: 组名称
    - listen_addr: 监听地址
    - key(可选): 预共享密钥, 不设置则不开启加密
    - enable_key_rotation(可选): 基于时间的密钥轮换，要求节点之间的系统时间尽可能的同步, 默认为false
    - address_range: 网段