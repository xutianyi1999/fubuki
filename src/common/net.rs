use std::io::Result;
use std::net::{IpAddr, SocketAddr};

use socket2::{Socket, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::Duration;

pub trait TcpSocketExt {
    fn set_keepalive(&self) -> Result<()>;
}

impl TcpSocketExt for TcpStream {
    fn set_keepalive(&self) -> Result<()> {
        set_keepalive(self)
    }
}

impl TcpSocketExt for TcpSocket {
    fn set_keepalive(&self) -> Result<()> {
        set_keepalive(self)
    }
}

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

#[cfg(windows)]
fn set_keepalive<S: std::os::windows::io::AsRawSocket>(socket: &S) -> Result<()> {
    use std::os::windows::io::FromRawSocket;

    unsafe {
        let socket = Socket::from_raw_socket(socket.as_raw_socket());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

#[cfg(unix)]
fn set_keepalive<S: std::os::unix::io::AsRawFd>(socket: &S) -> Result<()> {
    use std::os::unix::io::FromRawFd;

    unsafe {
        let socket = Socket::from_raw_fd(socket.as_raw_fd());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

pub async fn get_interface_addr(dest_addr: SocketAddr) -> Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(dest_addr).await?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}

pub mod proto {
    use std::collections::HashMap;
    use std::io;
    use std::io::Result;
    use std::net::{Ipv4Addr, SocketAddr};

    use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
    use crypto::rc4::Rc4;
    use crypto::symmetriccipher::Encryptor;
    use serde::{Deserialize, Serialize};

    use crate::common::persistence::ToJson;

    pub const MTU: usize = 1450;

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

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Node {
        pub id: NodeId,
        pub tun_addr: Ipv4Addr,
        pub lan_udp_addr: Option<SocketAddr>,
        pub wan_udp_addr: Option<SocketAddr>,
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
        Heartbeat(NodeId, Seq, HeartbeatType),
    }

    impl TcpMsg<'_> {
        pub fn encode<'a>(&self, buff: &'a mut [u8]) -> Result<&'a [u8]> {
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
                        MsgResult::Timeout => slice[1] = TIMEOUT
                    };
                    2
                }
                TcpMsg::Forward(data, node_id) => {
                    slice[0] = FORWARD;
                    slice[1..5].copy_from_slice(&node_id.to_be_bytes());
                    slice[5..data.len() + 5].copy_from_slice(*data);
                    data.len() + 5
                }
                TcpMsg::Heartbeat(node_id, seq, heartbeat_type) => {
                    slice[0] = HEARTBEAT;
                    slice[1..5].copy_from_slice(&node_id.to_be_bytes());
                    slice[5..9].copy_from_slice(&seq.to_be_bytes());

                    let type_byte = match heartbeat_type {
                        HeartbeatType::Req => REQ,
                        HeartbeatType::Resp => RESP
                    };

                    slice[9] = type_byte;
                    10
                }
            };
            Ok(&buff[..len + 1])
        }

        pub fn decode(packet: &[u8]) -> Result<TcpMsg> {
            let magic_num = packet[0];
            let mode = packet[1];
            let data = &packet[2..];

            if magic_num != MAGIC_NUM {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "TCP Message error"));
            }

            let msg = match mode {
                REGISTER => {
                    let node: Node = serde_json::from_slice(data)?;
                    TcpMsg::Register(node)
                }
                RESULT => {
                    match data[0] {
                        SUCCESS => TcpMsg::Result(MsgResult::Success),
                        TIMEOUT => TcpMsg::Result(MsgResult::Timeout),
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "TCP Message error"))
                    }
                }
                NODE_MAP => {
                    let node_map: HashMap<NodeId, Node> = serde_json::from_slice(data)?;
                    TcpMsg::NodeMap(node_map)
                }
                FORWARD => {
                    let mut node_id_buff = [0u8; 4];
                    node_id_buff.copy_from_slice(&data[..4]);
                    let node_id = NodeId::from_be_bytes(node_id_buff);

                    TcpMsg::Forward(&data[4..], node_id)
                }
                HEARTBEAT => {
                    let mut node_id = [0u8; 4];
                    node_id.copy_from_slice(&data[..4]);
                    let node_id: NodeId = u32::from_be_bytes(node_id);

                    let mut seq = [0u8; 4];
                    seq.copy_from_slice(&data[4..8]);
                    let seq: Seq = u32::from_be_bytes(seq);

                    let heartbeat_type = data[8];

                    let heartbeat_type = match heartbeat_type {
                        REQ => HeartbeatType::Req,
                        RESP => HeartbeatType::Resp,
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP Message error"))
                    };
                    TcpMsg::Heartbeat(node_id, seq, heartbeat_type)
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "TCP Message error"))
            };
            Ok(msg)
        }
    }

    pub enum UdpMsg<'a> {
        Heartbeat(NodeId, Seq, HeartbeatType),
        Data(&'a [u8]),
    }

    impl<'a> UdpMsg<'a> {
        pub fn encode(&self, buff: &'a mut [u8]) -> Result<&'a [u8]> {
            buff[0] = MAGIC_NUM;
            let slice = &mut buff[1..];

            let len = match self {
                UdpMsg::Heartbeat(node_id, seq, heartbeat_type) => {
                    slice[0] = HEARTBEAT;
                    slice[1..5].copy_from_slice(&node_id.to_be_bytes());
                    slice[5..9].copy_from_slice(&seq.to_be_bytes());

                    let type_byte = match heartbeat_type {
                        HeartbeatType::Req => REQ,
                        HeartbeatType::Resp => RESP
                    };

                    slice[9] = type_byte;
                    10
                }
                UdpMsg::Data(data) => {
                    slice[0] = DATA;
                    slice[1..data.len() + 1].copy_from_slice(*data);
                    data.len() + 1
                }
            };

            Ok(&buff[..len + 1])
        }

        pub fn decode(packet: &'a [u8]) -> Result<Self> {
            let magic_num = packet[0];
            let mode = packet[1];
            let data = &packet[2..];

            if magic_num != MAGIC_NUM {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP Message error"));
            }

            match mode {
                DATA => {
                    Ok(UdpMsg::Data(data))
                }
                HEARTBEAT => {
                    let mut node_id = [0u8; 4];
                    node_id.copy_from_slice(&data[..4]);
                    let node_id: NodeId = u32::from_be_bytes(node_id);

                    let mut seq = [0u8; 4];
                    seq.copy_from_slice(&data[4..8]);
                    let seq: Seq = u32::from_be_bytes(seq);

                    let heartbeat_type = data[8];

                    let heartbeat_type = match heartbeat_type {
                        REQ => HeartbeatType::Req,
                        RESP => HeartbeatType::Resp,
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP Message error"))
                    };
                    Ok(UdpMsg::Heartbeat(node_id, seq, heartbeat_type))
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP Message error"))
            }
        }
    }

    pub fn crypto<'a>(input: &[u8], output: &'a mut [u8], rc4: &mut Rc4) -> Result<&'a [u8]> {
        let mut ref_read_buf = RefReadBuffer::new(input);
        let mut ref_write_buf = RefWriteBuffer::new(output);

        rc4.encrypt(&mut ref_read_buf, &mut ref_write_buf, false)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Crypto error"))?;
        Ok(&output[..input.len()])
    }
}

pub mod msg_operator {
    use std::io::Result;
    use std::net::SocketAddr;

    use crypto::rc4::Rc4;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use super::proto;
    use super::proto::{TcpMsg, UdpMsg};

    const UDP_BUFF_SIZE: usize = 2048;
    pub const TCP_BUFF_SIZE: usize = 65536;

    pub struct TcpMsgReader<'a, Rx: AsyncRead + Unpin> {
        rx: &'a mut Rx,
        rc4: &'a mut Rc4,
        buff: Box<[u8]>,
        out: Box<[u8]>,
    }

    impl<'a, Rx: AsyncRead + Unpin> TcpMsgReader<'a, Rx> {
        pub fn new(rx: &'a mut Rx, rc4: &'a mut Rc4) -> Self {
            let buff = vec![0u8; TCP_BUFF_SIZE].into_boxed_slice();
            let out = vec![0u8; TCP_BUFF_SIZE].into_boxed_slice();
            TcpMsgReader { rx, rc4, buff, out }
        }

        pub async fn read(&mut self) -> Result<TcpMsg<'_>> {
            let buff = &mut self.buff;
            let out = &mut self.out;
            let rx = &mut self.rx;
            let rc4 = &mut self.rc4;

            let len = rx.read_u16().await?;
            let data = &mut buff[..len as usize];
            rx.read_exact(data).await?;

            let out = proto::crypto(data, out, rc4)?;
            Ok(TcpMsg::decode(out)?)
        }
    }

    pub struct TcpMsgWriter<'a, Tx: AsyncWrite + Unpin> {
        tx: &'a mut Tx,
        rc4: &'a mut Rc4,
        buff: Box<[u8]>,
        out: Box<[u8]>,
    }

    impl<'a, Tx: AsyncWrite + Unpin> TcpMsgWriter<'a, Tx> {
        pub fn new(tx: &'a mut Tx, rc4: &'a mut Rc4) -> Self {
            let buff = vec![0u8; TCP_BUFF_SIZE].into_boxed_slice();
            let out = vec![0u8; TCP_BUFF_SIZE].into_boxed_slice();
            TcpMsgWriter { tx, rc4, buff, out }
        }

        pub async fn write(&mut self, msg: &TcpMsg<'_>) -> Result<()> {
            let buff = &mut self.buff;
            let out = &mut self.out;
            let tx = &mut self.tx;
            let rc4 = &mut self.rc4;

            let data = msg.encode(buff)?;
            let out = proto::crypto(data, out, rc4)?;

            let len = out.len();
            buff[..2].copy_from_slice(&(len as u16).to_be_bytes());
            buff[2..len + 2].copy_from_slice(out);

            tx.write_all(&buff[..len + 2]).await?;
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct UdpMsgSocket<'a> {
        socket: &'a UdpSocket,
        rc4: Rc4,
        buff: [u8; UDP_BUFF_SIZE],
        out: [u8; UDP_BUFF_SIZE],
    }

    impl<'a> UdpMsgSocket<'a> {
        pub fn new(socket: &'a UdpSocket, rc4: Rc4) -> Self {
            UdpMsgSocket { socket, rc4, buff: [0u8; UDP_BUFF_SIZE], out: [0u8; UDP_BUFF_SIZE] }
        }

        pub async fn read(&mut self) -> Result<(UdpMsg<'_>, SocketAddr)> {
            let socket = self.socket;
            let mut rc4 = self.rc4;
            let buff = &mut self.buff;
            let out = &mut self.out;

            let (len, peer_addr) = socket.recv_from(buff).await?;
            let data = &buff[..len];
            let packet = proto::crypto(data, out, &mut rc4)?;

            Ok((UdpMsg::decode(packet)?, peer_addr))
        }

        pub async fn write(&mut self, msg: &UdpMsg<'_>, dest_addr: SocketAddr) -> Result<()> {
            let socket = self.socket;
            let mut rc4 = self.rc4;
            let buff = &mut self.buff;
            let out = &mut self.out;

            let data = msg.encode(buff)?;
            let packet = proto::crypto(data, out, &mut rc4)?;
            socket.send_to(packet, dest_addr).await?;
            Ok(())
        }
    }
}