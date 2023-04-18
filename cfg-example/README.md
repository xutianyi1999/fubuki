### client-conf.json

```json
{
  "mtu": 1458,
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
  "allowed_ips": ["192.168.200.0/24"],
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
        "direct": ["UDP"],
        "relay": ["UDP", "TCP"]
      },
      "lan_ip_addr": "192.168.0.2",
      "ips": {
        "10.0.0.2": ["192.168.201.0/24"]
      }
    }
  ]
}
```

- mtu(可选): MTU，默认1458
- channel_limit(可选): 从TUN转发至server的队列大小，超过limit丢包，默认100
- api_addr(可选): API监听地址，默认`127.0.0.1:3030`
- tcp_heartbeat_interval_secs(可选): TCP 心跳包发送间隔，默认5秒
- udp_heartbeat_interval_secs(可选): UDP 心跳包发送间隔，默认5秒
- tcp_heartbeat_continuous_loss(可选): TCP 心跳包连续丢失次数，等于或超过次数则中断连接，默认5
- udp_heartbeat_continuous_loss(可选): UDP 心跳包连续丢失次数，等于或超过次数则代表目标不可用，默认5
- udp_heartbeat_continuous_recv(可选): UDP 心跳包连续接收，当到达则变更状态从不可用为可用，默认3
- reconnect_interval_secs(可选): TCP 重连间隔，默认3秒
- udp_socket_recv_buffer_size(可选): UDP socket 接收缓冲区，默认为系统默认值
- udp_socket_send_buffer_size(可选): UDP socket 发送缓冲区，默认为系统默认值
- allowed_ips(可选): 允许其余节点通过本地节点转至发目的网段
- groups: 配置多组网段
    - node_name: 节点名称
    - server_addr: 该网段发现服务器与中转服务器地址
    - tun_addr(可选): 本地节点的IP地址与掩码，默认从地址池获取
        - ip: 节点IP地址
        - netmask: 子网掩码
    - key: 预共享密钥
    - mode(可选): 数据传递方式，默认直连为UDP，中转优先使用UDP，备选TCP
        - direct: 直连的协议，目前仅支持UDP
        - relay: 中转的协议，支持UDP与TCP
    - lan_ip_addr(可选): 默认通过本地路由表选择, 可以手动指定LAN地址
    - ips(可选): 发送至目标网段的数据通过另一个节点去转发，例如通过'10.0.0.2'节点发送至目标'192.168.201.0/24'网段的机器

### server-config.json

```json
{
  "channel_limit": 100,
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
      "address_range": "10.0.0.0/24"
    }
  ]
}

```

- channel_limit(可选): 转发队列大小，超过limit丢包，默认100
- tcp_heartbeat_interval_secs(可选): TCP 心跳包发送间隔，最长10秒，5秒
- tcp_heartbeat_continuous_loss(可选): TCP 心跳包连续丢失次数，等于或超过次数则中断连接，默认5
- udp_heartbeat_interval_secs(可选): UDP 心跳包发送间隔，默认5秒
- udp_heartbeat_continuous_loss(可选): UDP 心跳包连续丢失次数，等于或超过次数则代表目标不可用，默认5
- udp_heartbeat_continuous_recv(可选): UDP 心跳包连续接收，当到达则变更状态从不可用为可用，默认3
- groups 配置多组网段
    - name: 组名称
    - listen_addr: 监听地址
    - key: 预共享密钥
    - address_range: 网段