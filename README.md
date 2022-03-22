# fubuki

fubuki是网状结构VPN实现，类似与TincVPN的简单组网工具

当前支持的平台：

- Windows
- Linux

## 工作机制

它需要一台公网服务器来维持客户端节点的地址映射，节点相互P2P通信，节点之间可能因NAT受限等问题无法通信时会切换为服务端中继

## 使用

[配置文件说明](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)
### 前置依赖

#### Windows
需要wintun.dll(https://www.wintun.net) 与执行文件同目录或System32下，并且能以管理员权限运行

#### Linux
需要内核支持TUN模块

### 客户端命令
节点启动：

```shell
sudo ./fubuki client client-config.json
```
查看节点信息：
```shell
./fubuki info
```
或指定API地址
```shell
./fubuki info "127.0.0.1:1234"
```
### 服务端命令
服务端启动：
```shell
./fubuki server server-config.json
```

## 源码构建
安装Rust环境

Windows平台toolchain需要为MSVC

```shell
git clone https://github.com/xutianyi1999/fubuki;
cd fubuki;
cargo build --release;
```
