# fubuki

fubuki是网状结构VPN实现，类似与TincVPN的简单组网工具

当前支持的平台：

- Windows
- Linux

## 工作机制

它需要一台拥有公网的服务器来维持客户端节点的实际地址映射，客户端实现P2P通信，当客户端之间可能因为NAT受限等原因无法通信时会自动切换为服务端中继

## 使用

[配置文件样例](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)
### 前置依赖

#### Windows
需要wintun.dll(https://www.wintun.net)与执行文件同目录或System32下，并且能以管理员权限运行

#### Linux
需要内核支持tun模块

### 客户端命令
节点启动：

```shell
sudo ./fubuki client client-config.json
```
查看节点信息：
```shell
./fubuki info
```
### 服务端命令
服务端启动：
```shell
./fubuki server server-config.json
```
