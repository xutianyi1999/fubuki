# fubuki

Simple VPN implemented using rust

fubuki是类似与tincVPN的简单组网工具

当前支持的平台：

- Windows
- Linux

## 工作机制

它需要一台拥有公网的服务器来维持客户端节点的实际地址映射，客户端实现P2P通信，当客户端之间可能因为NAT受限等原因无法通信时会自动切换为服务端中转

## 使用

[配置文件样例](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)

#### 客户端

#### Windows

下载wintun(https://www.wintun.net/)

将wintun.dll和fubuki.exe保持相同目录

在管理员模式运行

```shell
.\fubuki.exe client client-config.json
```
stdin "show" 可以打印接入的客户端
#### Linux

需要内核支持tun模块

```shell
sudo ./fubuki client client-config.json
```

#### 服务端

```shell
.\fubuki.exe server server-config.json
```
