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

- mtu(可选): MTU，IPV4默认1444，IPV6默认1424
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
- external_routing_table(可选): 外部路由表, 路径为程序同目录`fubukiextrt`(Windows)的动态库, Unix平台为`libfubukiextrt`，[实现细节](https://github.com/xutianyi1999/fubuki/blob/master/src/routing_table/external.rs)
- allow_packet_forward(可选): 允许转发目标地址不是自己的数据包, 默认为true
- allow_packet_not_in_rules_send_to_kernel(可选): 允许目标地址不符合规则的包写入内核, 默认为false
- enable_hook(可选): 外部钩子, 路径为程序同目录`fubukihook`(Windows)的动态库, Unix平台为`libfubukhook`，[实现细节](https://github.com/xutianyi1999/fubuki/blob/master/src/common/hook.rs)
- socket_bind_device(可选): 监听的socket从指定网卡发送数据包, 在Windows上是`WLAN`、`Ethernet`类似的网卡名称, Linux上则是`eth0`类似网卡名称
- cross_nat(可选): 用于替换当前平台系统nat组件, 推荐在系统nat不可用时启用, 仅在配置`allowed_ips`时生效, 默认为false
- groups: 配置多组网段
    - node_name(可选): 节点名称, 默认主机名
    - server_addr: 该网段发现服务器与中转服务器地址
    - tun_addr(可选): 本地节点的IP地址与掩码，默认从地址池获取
        - ip: 节点IP地址
        - netmask: 子网掩码
    - key(可选): 预共享密钥, 不设置则不开启加密
    - mode(可选): 数据传输方式，默认直连为UDP，中转优先使用UDP，备选TCP
        - p2p: 直连的协议，目前仅支持UDP
        - relay: 中转的协议，支持UDP与TCP
    - specify_mode(可选): 指定到目标节点的数据传输方式, 仅覆盖当前节点到目标节点的数据上传流量, 目前有一些局限, 如mode未设置p2p, specify_mode启用p2p并不能生效
    - lan_ip_addr(可选): 默认通过本地路由表选择, 可以手动指定LAN地址
    - node_binding(可选): 指定 Node UDPSocket 监听地址, 默认为`0.0.0.0:0` 或 `[::]:0`
    - allowed_ips(可选): 允许其余节点通过本地节点转至发目的网段
    - ips(可选): 发送至目标网段的数据通过另一个节点去转发，例如通过`10.0.0.2`节点发送至目标`192.168.201.0/24`网段的机器
    - auto_route_selection(可选): 与目标节点无法p2p时会自动寻找一个合适的中间节点去转发, 当可能途经多个中转节点时需要所有节点都开启此选项
    - use_kcp_session(可选): 默认使用tcp进行节点的会话维持, 但是如果遇到tcp干扰可以开启该选项使用kcp代替, 默认为false
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
    - address_range: 网段
    - flow_control_rules(可选): 目标网段中转流量规则, 只限制目标下行
      - ["目标网段", "单个节点每秒流量"]
    - allow_udp_relay(可选): 是否允许UDP中继，默认为true
    - allow_tcp_relay(可选): 是否允许TCP中继，默认为true