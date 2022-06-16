### client-conf.json

```json
{
  "mtu": 1462,
  "channel_limit": 100,
  "api_addr": "127.0.0.1:3030",
  "tcp_heartbeat_interval_secs": 5,
  "udp_heartbeat_interval_secs": 5,
  "reconnect_interval_secs": 3,
  "udp_socket_recv_buffer_size": 8192,
  "udp_socket_send_buffer_size": 8192,
  "tun_handler_thread_count": 1,
  "udp_handler_thread_count": 1,
  "network_ranges": [
    {
      "server_addr": "192.168.1.10:12345",
      "tun": {
        "ip": "10.0.0.1",
        "netmask": "255.255.255.0"
      },
      "key": "a123",
      "mode": "UDP_AND_TCP",
      "lan_ip_addr": "192.168.0.2",
      "try_send_to_lan_addr": false
    }
  ]
}
```

- mtu(可选): MTU，默认1462
- channel_limit(可选): TUN发送至Server的队列大小，超过limit丢包，默认100
- api_addr(可选): 客户端API监听地址，默认`127.0.0.1:3030`
- tcp_heartbeat_interval_secs(可选): TCP 心跳包发送周期，最长10秒，默认5秒
- udp_heartbeat_interval_secs(可选): UDP 心跳包发送周期，最长10秒，默认5秒
- reconnect_interval_secs(可选): 重连间隔，默认3秒
- udp_socket_recv_buffer_size(可选): UDP socket 接收缓冲区，默认为系统默认值
- udp_socket_send_buffer_size(可选): UDP socket 发送缓冲区，默认为系统默认值
- tun_handler_thread_count(可选): TUN处理器线程数，适当增加可以提高吞吐，默认1
- udp_handler_thread_count(可选): UDP处理器线程数，适当增加可以提高吞吐，默认1
- network_ranges 配置多网段
    - server_addr: 该网段发现服务器与中转服务器
    - tun
        - ip: TUN网卡IP地址
        - netmask: 子网掩码
    - key: 预共享密钥
    - mode(可选): 模式`UDP_ONLY`, `TCP_ONLY`, `UDP_AND_TCP`, 默认为`UDP_AND_TCP`
    - lan_ip_addr(可选): 默认通过本地路由表选择, 可以手动指定LAN地址
    - try_send_to_lan_addr(可选): 多个节点在同一NAT之后无法直接通信时可以开启此选项，默认为false

### server-config.json

```json
{
  "channel_limit": 100,
  "tcp_heartbeat_interval_secs": 5,
  "listeners": [
    {
      "listen_addr": "0.0.0.0:12345",
      "key": "a123"
    }
  ]
}
```

- channel_limit(可选): 转发队列，超过limit丢包，默认100
- tcp_heartbeat_interval_secs(可选): TCP 心跳包发送周期，最长10秒，默认5秒
- listeners 配置多网段
    - listen_addr: 监听地址
    - key: 预共享密钥