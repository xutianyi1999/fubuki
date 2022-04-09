use std::io::Result;
use std::net::{IpAddr, ToSocketAddrs};

use socket2::TcpKeepalive;
use tokio::time::Duration;

pub trait SocketExt {
    fn set_keepalive(&self) -> Result<()>;

    fn set_recv_buffer_size(&self, size: usize) -> Result<()>;

    fn set_send_buffer_size(&self, size: usize) -> Result<()>;
}

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

macro_rules! build_socket_ext {
    ($type:path) => {
        impl<T: $type> SocketExt for T {
            fn set_keepalive(&self) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_tcp_keepalive(&TCP_KEEPALIVE)
            }

            fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_recv_buffer_size(size)
            }

            fn set_send_buffer_size(&self, size: usize) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_send_buffer_size(size)
            }
        }
    };
}

#[cfg(windows)]
build_socket_ext!(std::os::windows::io::AsRawSocket);

#[cfg(unix)]
build_socket_ext!(std::os::unix::io::AsRawFd);

pub fn get_interface_addr<A: ToSocketAddrs>(dest_addr: A) -> Result<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(dest_addr)?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}

pub mod proto {
    use std::fmt::{Display, Formatter};
    use std::io;
    use std::io::Result;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::ops::Range;
    use std::str::FromStr;

    use crate::common::HashMap;
    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};

    use crate::common::persistence::ToJson;

    const MAGIC_NUM: u8 = 0x99;
    const REGISTER: u8 = 0x00;
    const NODE_MAP: u8 = 0x01;
    const HEARTBEAT: u8 = 0x02;
    const DATA: u8 = 0x03;
    const FORWARD: u8 = 0x04;
    const RESULT: u8 = 0x05;
    const REQ: u8 = 0x00;
    const RESP: u8 = 0x01;
    const SUCCESS: u8 = 0x00;
    const TIMEOUT: u8 = 0x01;

    pub type NodeId = u32;
    pub type Seq = u32;

    #[derive(Copy, Clone, Serialize, Deserialize, PartialEq)]
    pub enum ProtocolMode {
        UdpOnly,
        TcpOnly,
        UdpAndTcp,
    }

    impl ProtocolMode {
        pub fn tcp_support(self) -> bool {
            self == ProtocolMode::TcpOnly || self == ProtocolMode::UdpAndTcp
        }

        pub fn udp_support(self) -> bool {
            self == ProtocolMode::UdpOnly || self == ProtocolMode::UdpAndTcp
        }
    }

    impl FromStr for ProtocolMode {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> anyhow::Result<Self> {
            let mode = match s.to_ascii_uppercase().as_str() {
                "UDP_ONLY" => ProtocolMode::UdpOnly,
                "TCP_ONLY" => ProtocolMode::TcpOnly,
                "UDP_AND_TCP" => ProtocolMode::UdpAndTcp,
                _ => return Err(anyhow!("Invalid protocol mode")),
            };
            Ok(mode)
        }
    }

    impl Display for ProtocolMode {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let str = match self {
                ProtocolMode::UdpOnly => "UDP_ONLY",
                ProtocolMode::TcpOnly => "TCP_ONLY",
                ProtocolMode::UdpAndTcp => "UDP_AND_TCP",
            };
            write!(f, "{}", str)
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Node {
        pub id: NodeId,
        pub tun_addr: Ipv4Addr,
        pub lan_udp_addr: Option<SocketAddr>,
        pub wan_udp_addr: Option<SocketAddr>,
        pub mode: ProtocolMode,
        pub register_time: i64,
    }

    pub enum HeartbeatType {
        Req,
        Resp,
    }

    pub enum MsgResult {
        Success,
        Timeout,
    }

    pub enum TcpMsg<'a> {
        Register(Node),
        Result(MsgResult),
        NodeMap(HashMap<NodeId, Node>),
        Forward(&'a [u8], NodeId),
        Heartbeat(Seq, HeartbeatType),
    }

    macro_rules! get {
        ($slice: expr, $index: expr, $error_msg: expr) => {
            $slice
                .get($index)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, $error_msg))?
        };
        ($slice: expr, $index: expr) => {
            get!($slice, $index, "Decode error")
        };
    }

    impl TcpMsg<'_> {
        pub fn encode<'a>(&self, buff: &'a mut [u8]) -> Result<&'a mut [u8]> {
            buff[0] = MAGIC_NUM;
            let slice = &mut buff[1..];

            let len = match self {
                TcpMsg::NodeMap(node_map) => {
                    let data = node_map.to_json_vec()?;
                    slice[0] = NODE_MAP;
                    slice[1..data.len() + 1].copy_from_slice(&data);
                    data.len() + 1
                }
                TcpMsg::Register(node) => {
                    let data = node.to_json_vec()?;
                    slice[0] = REGISTER;
                    slice[1..data.len() + 1].copy_from_slice(&data);
                    data.len() + 1
                }
                TcpMsg::Result(res) => {
                    slice[0] = RESULT;

                    match res {
                        MsgResult::Success => slice[1] = SUCCESS,
                        MsgResult::Timeout => slice[1] = TIMEOUT,
                    };
                    2
                }
                TcpMsg::Forward(data, node_id) => {
                    slice[0] = FORWARD;
                    slice[1..5].copy_from_slice(&node_id.to_be_bytes());
                    slice[5..data.len() + 5].copy_from_slice(*data);
                    data.len() + 5
                }
                TcpMsg::Heartbeat(seq, heartbeat_type) => {
                    slice[0] = HEARTBEAT;
                    slice[1..5].copy_from_slice(&seq.to_be_bytes());

                    let type_byte = match heartbeat_type {
                        HeartbeatType::Req => REQ,
                        HeartbeatType::Resp => RESP,
                    };

                    slice[5] = type_byte;
                    6
                }
            };
            Ok(&mut buff[..len + 1])
        }

        pub fn decode(packet: &[u8]) -> Result<TcpMsg> {
            let magic_num = *get!(packet, 0);
            let mode = *get!(packet, 1);
            let data = get!(packet, 2..);

            if magic_num != MAGIC_NUM {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TCP Message error",
                ));
            }

            let msg = match mode {
                REGISTER => {
                    let node: Node = serde_json::from_slice(data)?;
                    TcpMsg::Register(node)
                }
                RESULT => match data[0] {
                    SUCCESS => TcpMsg::Result(MsgResult::Success),
                    TIMEOUT => TcpMsg::Result(MsgResult::Timeout),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TCP Message error",
                        ));
                    }
                },
                NODE_MAP => {
                    let node_map: HashMap<NodeId, Node> = serde_json::from_slice(data)?;
                    TcpMsg::NodeMap(node_map)
                }
                FORWARD => {
                    let mut node_id_buff = [0u8; 4];
                    node_id_buff.copy_from_slice(get!(data, ..4));
                    let node_id = NodeId::from_be_bytes(node_id_buff);

                    TcpMsg::Forward(get!(data, 4..), node_id)
                }
                HEARTBEAT => {
                    let mut seq = [0u8; 4];
                    seq.copy_from_slice(get!(data, ..4));
                    let seq: Seq = u32::from_be_bytes(seq);

                    let heartbeat_type = *get!(data, 4);

                    let heartbeat_type = match heartbeat_type {
                        REQ => HeartbeatType::Req,
                        RESP => HeartbeatType::Resp,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "TCP Message error",
                            ));
                        }
                    };
                    TcpMsg::Heartbeat(seq, heartbeat_type)
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TCP Message error",
                    ));
                }
            };
            Ok(msg)
        }
    }

    pub enum UdpMsg<'a> {
        Heartbeat(NodeId, Seq, HeartbeatType),
        Data(&'a [u8]),
    }

    impl<'a> UdpMsg<'a> {
        pub fn encode(&self, buff: &'a mut [u8]) -> &'a mut [u8] {
            buff[0] = MAGIC_NUM;
            let slice = &mut buff[1..];

            let len = match self {
                UdpMsg::Heartbeat(node_id, seq, heartbeat_type) => {
                    slice[0] = HEARTBEAT;
                    slice[1..5].copy_from_slice(&node_id.to_be_bytes());
                    slice[5..9].copy_from_slice(&seq.to_be_bytes());

                    let type_byte = match heartbeat_type {
                        HeartbeatType::Req => REQ,
                        HeartbeatType::Resp => RESP,
                    };

                    slice[9] = type_byte;
                    10
                }
                UdpMsg::Data(data) => {
                    slice[0] = DATA;
                    data.len() + 1
                }
            };

            &mut buff[..len + 1]
        }

        pub fn decode(packet: &'a [u8]) -> Result<Self> {
            let magic_num = *get!(packet, 0);
            let mode = *get!(packet, 1);
            let data = get!(packet, 2..);

            if magic_num != MAGIC_NUM {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP Message error",
                ));
            }

            match mode {
                DATA => Ok(UdpMsg::Data(data)),
                HEARTBEAT => {
                    let mut node_id = [0u8; 4];
                    node_id.copy_from_slice(get!(data, ..4));
                    let node_id: NodeId = u32::from_be_bytes(node_id);

                    let mut seq = [0u8; 4];
                    seq.copy_from_slice(get!(data, 4..8));
                    let seq: Seq = u32::from_be_bytes(seq);

                    let heartbeat_type = *get!(data, 8);

                    let heartbeat_type = match heartbeat_type {
                        REQ => HeartbeatType::Req,
                        RESP => HeartbeatType::Resp,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "UDP Message error",
                            ));
                        }
                    };
                    Ok(UdpMsg::Heartbeat(node_id, seq, heartbeat_type))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP Message error",
                )),
            }
        }
    }

    const SRC_ADDR: Range<usize> = 12..16;
    const DST_ADDR: Range<usize> = 16..20;

    pub fn get_ip_dst_addr(ip_packet: &[u8]) -> Result<Ipv4Addr> {
        let mut buff = [0u8; 4];
        buff.copy_from_slice(get!(ip_packet, DST_ADDR, "Get ip packet dst addr error"));
        Ok(Ipv4Addr::from(buff))
    }

    pub fn get_ip_src_addr(ip_packet: &[u8]) -> Result<Ipv4Addr> {
        let mut buff = [0u8; 4];
        buff.copy_from_slice(get!(ip_packet, SRC_ADDR, "Get ip packet src addr error"));
        Ok(Ipv4Addr::from(buff))
    }
}

pub mod msg_operator {
    use std::io::Result;
    use std::net::SocketAddr;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use crate::common::cipher::Aes128Ctr;

    use super::proto::{TcpMsg, UdpMsg};

    pub const UDP_BUFF_SIZE: usize = 65536;
    pub const TCP_BUFF_SIZE: usize = 65536;

    pub struct TcpMsgReader<'a, Rx: AsyncRead + Unpin> {
        rx: &'a mut Rx,
        key: &'a mut Aes128Ctr,
        buff: Box<[u8]>,
    }

    impl<'a, Rx: AsyncRead + Unpin> TcpMsgReader<'a, Rx> {
        pub fn new(rx: &'a mut Rx, key: &'a mut Aes128Ctr) -> Self {
            let buff = vec![0u8; TCP_BUFF_SIZE].into_boxed_slice();
            TcpMsgReader { rx, key, buff }
        }

        pub async fn read(&mut self) -> Result<TcpMsg<'_>> {
            let buff = &mut self.buff;
            let rx = &mut self.rx;
            let key = &mut self.key;

            let len = rx.read_u16().await?;
            let data = &mut buff[..len as usize];
            rx.read_exact(data).await?;

            key.decrypt_slice(data);
            TcpMsg::decode(data)
        }
    }

    pub struct TcpMsgWriter<'a, Tx: AsyncWrite + Unpin> {
        tx: &'a mut Tx,
        key: &'a mut Aes128Ctr,
        buff: Box<[u8]>,
    }

    impl<'a, Tx: AsyncWrite + Unpin> TcpMsgWriter<'a, Tx> {
        pub fn new(tx: &'a mut Tx, key: &'a mut Aes128Ctr) -> Self {
            let buff = vec![0u8; TCP_BUFF_SIZE].into_boxed_slice();
            TcpMsgWriter { tx, key, buff }
        }

        pub async fn write(&mut self, msg: &TcpMsg<'_>) -> Result<()> {
            let buff = &mut self.buff;
            let tx = &mut self.tx;
            let key = &mut self.key;

            let data = msg.encode(&mut buff[2..])?;
            key.encrypt_slice(data);

            let len = data.len();
            buff[..2].copy_from_slice(&(len as u16).to_be_bytes());

            tx.write_all(&buff[..len + 2]).await?;
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct UdpMsgSocket<'a> {
        socket: &'a UdpSocket,
        key: Aes128Ctr,
        buff: Box<[u8]>,
    }

    impl<'a> UdpMsgSocket<'a> {
        pub fn new(socket: &'a UdpSocket, key: Aes128Ctr) -> Self {
            UdpMsgSocket {
                socket,
                key,
                buff: vec![0u8; UDP_BUFF_SIZE].into_boxed_slice(),
            }
        }

        pub async fn read(&mut self) -> Result<(UdpMsg<'_>, SocketAddr)> {
            let socket = self.socket;
            let mut key = self.key.clone();
            let buff = &mut self.buff;

            let (len, peer_addr) = socket.recv_from(buff).await?;
            let data = &mut buff[..len];
            key.decrypt_slice(data);

            Ok((UdpMsg::decode(data)?, peer_addr))
        }

        // TODO unsupported UdpMsg::Data type
        pub async fn write(&mut self, msg: &UdpMsg<'_>, dest_addr: SocketAddr) -> Result<()> {
            let socket = self.socket;
            let mut key = self.key.clone();
            let buff = &mut self.buff;

            let data = msg.encode(buff);
            key.encrypt_slice(data);
            socket.send_to(data, dest_addr).await?;
            Ok(())
        }
    }
}
