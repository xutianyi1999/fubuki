# fubuki
Simple VPN implemented using rust

fubuki是类似与tincVPN的简单组网工具

支持的平台：

- Windows
- Linux
  
## 工作机制

它由一台拥有公网IP的服务器来维持各个内网客户端的实际地址映射，在客户端和客户端之间实现P2P通信
![image.png](https://i.loli.net/2021/02/15/KuaUrMlzQRjZDfC.png)

## 使用

[配置文件样例](https://github.com/xutianyi1999/fubuki/tree/master/cfg-example)

#### 客户端

###### Windows

下载wintun(https://www.wintun.net/)

将wintun.dll和fubuki.exe保持相同目录

在管理员模式运行

```shell
.\fubuki.exe client client-config.json
```

###### Linux

需要内核支持tun模块

```shell
sudo ./fubuki client client-config.json
```

#### 服务端

```shell
.\fubuki.exe server server-config.json
```
