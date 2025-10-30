# fubuki

[![Release](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml/badge.svg)](https://github.com/xutianyi1999/fubuki/actions/workflows/rust.yml)

<!-- Keep these links. Translations will automatically update with the README. -->
[Deutsch](https://zdoc.app/de/xutianyi1999/fubuki) | 
[English](https://zdoc.app/en/xutianyi1999/fubuki) | 
[Español](https://zdoc.app/es/xutianyi1999/fubuki) | 
[français](https://zdoc.app/fr/xutianyi1999/fubuki) | 
[日本語](https://zdoc.app/ja/xutianyi1999/fubuki) | 
[한국어](https://zdoc.app/ko/xutianyi1999/fubuki) | 
[Português](https://zdoc.app/pt/xutianyi1999/fubuki) | 
[Русский](https://zdoc.app/ru/xutianyi1999/fubuki) | 
[中文](https://zdoc.app/zh/xutianyi1999/fubuki)


fubuki是网状VPN实现，用于不同内网机器之间相互通信

当前支持的平台：

- Windows
- Linux
- macOS
- Android

受支持的协议类型：

- P2P: UDP
- 中继: UDP, TCP

工作模式：

它通过一台公网服务器来同步多个节点的地址映射与存活状态。每个节点启动之后会存在一个唯一的虚拟地址，节点加入网段服务端会向所有对等节点同步状态信息并协调节点之间打洞，如受NAT限制等原因通讯建立失败后会回退至服务端中继。

## Usage

```shell
Usage: fubuki <COMMAND>

Commands:
  server  coordinator and data relay server
  node    fubuki node
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

[配置文档](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)

#### 前置依赖

##### Windows

- 必须以管理员权限运行
- 需要wintun.dll(https://www.wintun.net) 与程序同目录或System32下
- Windows7 需要安装 [KB3063858](https://www.microsoft.com/en-us/download/details.aspx?id=47409)、[KB4474419](https://www.catalog.update.microsoft.com/search.aspx?q=kb4474419) 这两个补丁

##### Linux

- 必须以root权限运行
- 内核需支持tun模块

##### macOS

- 必须以root权限运行
- 内核需支持tun模块

### Fubuki server

创建fubuki服务端的配置 server-config.json

```json
{
  "groups": [
    {
      "name": "mygroup",
      "key": "123",
      "listen_addr": "0.0.0.0:12345",
      "address_range": "10.0.0.0/24"
    }
  ]
}
```

- name: 组名为 "mygroup"
- key: 该组的预共享密钥
- listen_addr: fubuki server监听地址
- address_range: 配置的虚拟网段

启动 fubuki server

```shell
fubuki server daemon ./server-config.json
```

### Fubuki node

创建fubuki节点的配置 node-config.json

```json
{
  "groups": [
    {
      "node_name": "node1",
      "server_addr": "{fubuki server address}",
      "key": "123"
    }
  ]
}
```

- node_name: 节点名
- server_addr: 服务器地址，格式为 IP:PORT
- key: 预共享密钥

启动 fubuki node

```shell
fubuki node daemon ./node-config.json
```

启动第二个节点

```json
{
  "groups": [
    {
      "node_name": "node2",
      "server_addr": "{fubuki server address}",
      "key": "123"
    }
  ]
}
```

`ping` node2节点，可以使用 `{node_name}.{group_name}` 形式

```shell
ping node2.mygroup
```

## Build

- Rust nightly toolchain
- Windows 
  - MSVC toolchain

```shell
cargo +nightly build --release
```

包含 Web UI

- Node.js >= 16.*
- Angular CLI

```shell
cargo +nightly build --release --features "web"
```

包含 GUI

```shell
cargo +nightly build --release --features "gui"
```

交叉编译Android动态库
```shell
export RUSTUP_TOOLCHAIN=nightly
cargo install cross --git https://github.com/cross-rs/cross
# 这里的目标平台是aarch64-linux-android, 有关于其他Rust支持的平台参阅 https://doc.rust-lang.org/nightly/rustc/platform-support.html
cross +nightly build --lib --release --no-default-features --features "ffi-export" --target aarch64-linux-android
```
