use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes};
use chrono::Utc;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::Encryptor;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::common::persistence::ToJson;
use crate::common::proto::Msg::{Data, Heartbeat, NodeMap, NodeMapSerde, Register};

pub const MTU: usize = 1420;

const REGISTER: u8 = 0x00;
const NODE_MAP: u8 = 0x01;
const HEARTBEAT: u8 = 0x02;
const DATA: u8 = 0x03;

pub type NodeId = u32;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Node {
    pub id: NodeId,
    pub tun_addr: Ipv4Addr,
    pub lan_udp_addr: SocketAddr,
    pub source_udp_addr: Option<SocketAddr>,
    pub register_time: i64,
}

impl Node {
    pub fn from_slice(s: &[u8]) -> Result<Node, serde_json::Error> {
        serde_json::from_slice(s)
    }
}

pub enum Msg<'a> {
    Register(Node),
    NodeMap(HashMap<NodeId, Node>),
    NodeMapSerde(&'a [u8]),
    Heartbeat(NodeId),
    Data(&'a [u8]),
}

pub struct MsgReader<R>
    where R: AsyncRead
{
    rx: R,
    rc4: Rc4,
}

impl<R> MsgReader<R>
    where R: AsyncRead + Unpin
{
    pub fn new(rx: R, rc4: Rc4) -> Self {
        MsgReader { rx, rc4 }
    }

    pub async fn read_msg(&mut self) -> io::Result<Option<Msg<'_>>> {
        let rx = &mut self.rx;
        let rc4 = &mut self.rc4;

        let res = rx.read_u16().await;

        let len = match res {
            Ok(len) => len as usize,
            Err(_) => return Ok(None)
        };

        let mut data = vec![0u8; len];
        rx.read_exact(&mut data).await?;

        let mut out = vec![0u8; len];
        crypto(&data, &mut out, rc4)?;

        let mut data = Bytes::from(out);

        let mode = data.get_u8();

        match mode {
            REGISTER => {
                let node = Node::from_slice(&data).map_err(|e| io::Error::from(e))?;
                let old_time = node.register_time;
                let now = Utc::now().timestamp();
                let r = now - old_time;

                if (r > 10) || (r < -10) {
                    return Err(io::Error::new(io::ErrorKind::Other, "Message timeout"));
                }
                Ok(Some(Register(node)))
            }
            NODE_MAP => {
                let node_map: HashMap<NodeId, Node> = serde_json::from_slice(&data)?;
                Ok(Some(NodeMap(node_map)))
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "Config message error"))
        }
    }
}

pub struct MsgWriter<W>
    where W: AsyncWrite
{
    tx: W,
    rc4: Rc4,
}

impl<W> MsgWriter<W>
    where W: AsyncWrite + Unpin
{
    pub fn new(tx: W, rc4: Rc4) -> Self {
        MsgWriter { tx, rc4 }
    }

    pub async fn write_msg(&mut self, msg: Msg<'_>) -> io::Result<()> {
        let tx = &mut self.tx;
        let rc4 = &mut self.rc4;

        let data = match msg {
            Register(node) => {
                let v = node.to_json_vec()?;
                let len = v.len();
                let mut data: Vec<u8> = Vec::with_capacity(1 + len);

                data.put_u8(REGISTER);
                data.put_slice(&v);
                data
            }
            NodeMapSerde(json_vec) => {
                let len = json_vec.len();

                let mut data = Vec::with_capacity(1 + len);
                data.put_u8(NODE_MAP);
                data.put_slice(&json_vec);
                data
            }
            _ => panic!("Write message error")
        };

        let mut out = vec![0u8; data.len()];
        crypto(&data, &mut out, rc4)?;

        tx.write_u16(out.len() as u16).await?;
        tx.write_all(&out).await
    }
}

pub struct MsgSocket<'a> {
    socket: &'a UdpSocket,
    rc4: Rc4,
    buff: [u8; MTU + 1],
    out: [u8; MTU + 1],
}

impl MsgSocket<'_> {
    pub fn new(socket: &UdpSocket, rc4: Rc4) -> MsgSocket {
        MsgSocket { socket, rc4, buff: [0u8; MTU + 1], out: [0u8; MTU + 1] }
    }

    pub async fn recv_msg(&mut self) -> io::Result<(Msg<'_>, SocketAddr)> {
        let socket = self.socket;
        let mut rc4 = self.rc4;
        let buff = &mut self.buff;
        let out = &mut self.out;

        let (len, peer_addr) = socket.recv_from(buff).await?;
        let data = &buff[..len];

        let out = crypto(data, out, &mut rc4)?;

        let mode = out[0];

        match mode {
            HEARTBEAT => {
                let mut node_id = [0u8; 4];
                node_id.copy_from_slice(&out[1..5]);
                let node_id: NodeId = u32::from_be_bytes(node_id);
                Ok((Msg::Heartbeat(node_id), peer_addr))
            }
            DATA => {
                Ok((Msg::Data(&out[1..]), peer_addr))
            }
            _ => Err(io::Error::new(io::ErrorKind::Other, "Datagram message error"))
        }
    }

    pub async fn send_msg(&mut self, msg: Msg<'_>, peer_addr: SocketAddr) -> io::Result<()> {
        let socket = self.socket;
        let mut rc4 = self.rc4;
        let buff = &mut self.buff;
        let out = &mut self.out;

        let data = match msg {
            Heartbeat(node_id) => {
                buff[0] = HEARTBEAT;
                buff[1..5].copy_from_slice(&node_id.to_be_bytes());
                &buff[..5]
            }
            Data(data) => {
                let data_len = data.len();
                buff[0] = DATA;
                buff[1..(data_len + 1)].copy_from_slice(data);
                &buff[..(data_len + 1)]
            }
            _ => panic!("Send Message error")
        };

        let slice = crypto(data, out, &mut rc4)?;
        socket.send_to(slice, peer_addr).await?;
        Ok(())
    }
}

pub fn crypto<'a>(input: &[u8], output: &'a mut [u8], rc4: &mut Rc4) -> io::Result<&'a mut [u8]> {
    let mut ref_read_buf = RefReadBuffer::new(input);
    let mut ref_write_buf = RefWriteBuffer::new(output);

    rc4.encrypt(&mut ref_read_buf, &mut ref_write_buf, false)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Crypto error"))?;
    Ok(&mut output[..input.len()])
}

pub async fn get_interface_addr(dest_addr: SocketAddr) -> io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(dest_addr).await?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}
