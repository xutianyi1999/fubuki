# Fubuki v0.4.* 协议

## TCP msg

| 2byte        | 1byte        | 1byte | dynamic size |
|:-------------|:-------------|-------|--------------|
| length       | magic number | type  | data         |
| 报文长度，不包括长度字段 | 魔数           | 报文类型  | 数据           |

magic number: 0x99

除length字段都会被加密



### Data

#### Register

type: 0x00

value: Node结构体JSON序列化 (https://github.com/xutianyi1999/fubuki/blob/637d306d395b23a76423f9d4603dd6eafac615ba/src/common/net.rs#L122-L130)



#### Result

type: 0x05

value:

| type    | value | description |
|---------|-------|-------------|
| success | 0x00  | 成功          |
| timeout | 0x01  | 注册超过预期时间    |



#### NodeMap

type: 0x01

value: map (NodeId -> Node) JSON序列化



#### Forward

type: 0x04

value:

| 4byte   | dynamic size |
|---------|--------------|
| node id | data         |
| 目标节点ID  | 数据(IPV4报文)   |



#### Heartbeat

type: 0x02

value:

| 4byte   | 1byte                          |
|---------|--------------------------------|
| seq     | request:  0x00; response: 0x01 |
| 序列号, 自增 | 心跳包类型                          |



## UDP msg

| 1byte        | 1byte | dynamic size |
|--------------|-------|--------------|
| magic number | type  | data         |
| 魔数           | 报文类型  | 数据           |

magic number: 0x99

整个报文会被加密



### Data

#### Data

type: 0x03

value: IPV4报文



#### Heartbeat

type: 0x02

value: 

| 4byte                       | 4byte  | 1byte                          |
|-----------------------------|--------|--------------------------------|
| node id                     | seq    | request:  0x00; response: 0x01 |
| 发送给对等节点是目标id，发送给server是自己id | 序列号，自增 | 心跳包类型                          |

