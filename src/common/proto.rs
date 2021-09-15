use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::Encryptor;
use serde::{Deserialize, Serialize};

use crate::common::persistence::ToJson;

pub const MTU: usize = 1450;

const MAGIC_NUM: u8 = 0x99;
const REGISTER: u8 = 0x00;
const NODE_LIST: u8 = 0x01;
const HEARTBEAT: u8 = 0x02;
const DATA: u8 = 0x03;
const FORWARD: u8 = 0x04;
const REQ: u8 = 0x00;
const RESP: u8 = 0x01;

pub type NodeId = u32;
pub type Seq = u32;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Node {
    pub id: NodeId,
    pub tun_addr: Ipv4Addr,
    pub lan_udp_addr: Option<SocketAddr>,
    pub source_udp_addr: Option<SocketAddr>,
    pub register_time: String,
}

pub enum HeartbeatType {
    Req,
    Resp,
}

#[derive(Clone, Debug)]
pub enum TcpMsg<'a> {
    Register(Node),
    NodeList(Vec<Node>),
    Forward(&'a [u8], NodeId),
}

impl TcpMsg<'_> {
    pub fn encode<'a>(&self, buff: &'a mut [u8]) -> Result<&'a [u8], Box<dyn Error>> {
        buff[0] = MAGIC_NUM;
        let slice = &mut buff[1..];

        let len = match self {
            TcpMsg::NodeList(node_list) => {
                let data = node_list.to_json_vec()?;
                slice[0] = NODE_LIST;
                slice[1..data.len() + 1].copy_from_slice(&data);
                data.len() + 1
            }
            TcpMsg::Register(node) => {
                let data = node.to_json_vec()?;
                slice[0] = REGISTER;
                slice[1..data.len() + 1].copy_from_slice(&data);
                data.len() + 1
            }
            TcpMsg::Forward(data, node_id) => {
                slice[0] = FORWARD;
                slice[1..5].copy_from_slice(&node_id.to_be_bytes());
                slice[5..data.len() + 5].copy_from_slice(*data);
                data.len() + 5
            }
        };
        Ok(&buff[..len + 1])
    }

    pub fn decode(packet: &[u8]) -> Result<TcpMsg, Box<dyn Error>> {
        let magic_num = packet[0];
        let mode = packet[1];
        let data = &packet[2..];

        if magic_num != MAGIC_NUM {
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "TCP Message error")));
        }

        let msg = match mode {
            REGISTER => {
                let node: Node = serde_json::from_slice(data)?;
                TcpMsg::Register(node)
            }
            NODE_LIST => {
                let node_list: Vec<Node> = serde_json::from_slice(data)?;
                TcpMsg::NodeList(node_list)
            }
            FORWARD => {
                let mut node_id_buff = [0u8; 4];
                node_id_buff.copy_from_slice(&data[..4]);
                let node_id = NodeId::from_be_bytes(node_id_buff);

                TcpMsg::Forward(&data[4..], node_id)
            }
            _ => return Err(Box::new(io::Error::new(io::ErrorKind::Other, "TCP Message error")))
        };
        Ok(msg)
    }
}

pub enum UdpMsg<'a> {
    Heartbeat(NodeId, Seq, HeartbeatType),
    Data(&'a [u8]),
}

impl<'a> UdpMsg<'a> {
    pub fn encode(&self, buff: &'a mut [u8]) -> Result<&'a [u8], Box<dyn Error>> {
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

    pub fn decode(packet: &'a [u8]) -> Result<Self, Box<dyn Error>> {
        let magic_num = packet[0];
        let mode = packet[1];
        let data = &packet[2..];

        if magic_num != MAGIC_NUM {
            return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "UDP message error")));
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
                    _ => return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "UDP message error")))
                };
                Ok((UdpMsg::Heartbeat(node_id, seq, heartbeat_type)))
            }
            _ => return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "UDP message error")))
        }
    }
}

pub fn crypto<'a>(input: &[u8], output: &'a mut [u8], rc4: &mut Rc4) -> io::Result<&'a [u8]> {
    let mut ref_read_buf = RefReadBuffer::new(input);
    let mut ref_write_buf = RefWriteBuffer::new(output);

    rc4.encrypt(&mut ref_read_buf, &mut ref_write_buf, false)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Crypto error"))?;
    Ok(&output[..input.len()])
}