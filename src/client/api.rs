use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};

use anyhow::anyhow;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::client::{get_direct_node_list, get_interface_map};
use crate::common::net::proto::NodeId;
use crate::common::{HashMap, MapInit};

use crate::common::persistence::ToJson;
use crate::ProtocolMode;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeInfo {
    id: NodeId,
    tun_addr: Ipv4Addr,
    lan_udp_addr: Option<SocketAddr>,
    wan_udp_addr: Option<SocketAddr>,
    mode: ProtocolMode,
    register_time: i64,
    direct: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Req {
    NodeMap,
}

#[derive(Clone, Serialize, Deserialize)]
enum Resp<T> {
    Success(T),
    Error(String),
    Invalid(String),
}

pub async fn api_start(listen_addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        let (mut stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            let fut = async move {
                let mut buff = vec![0u8; 65536];

                let len = stream.read_u16().await? as usize;
                stream.read_exact(&mut buff[..len]).await?;

                let resp = match serde_json::from_slice::<Req>(&buff[..len]) {
                    Ok(Req::NodeMap) => {
                        let map = get_interface_map().load();
                        let direct_list = get_direct_node_list().load();

                        let mut node_map = HashMap::with_capacity(map.len());

                        for (k, v) in map {
                            let list: Vec<NodeInfo> = v
                                .node_map
                                .iter()
                                .map(|(_, node)| NodeInfo {
                                    id: node.id,
                                    tun_addr: node.tun_addr,
                                    lan_udp_addr: node.lan_udp_addr,
                                    wan_udp_addr: node.wan_udp_addr,
                                    mode: node.mode,
                                    register_time: node.register_time,
                                    direct: direct_list.contains(&node.id),
                                })
                                .collect();

                            node_map.insert(k, list);
                        }
                        Resp::Success(node_map)
                    }
                    Err(e) => Resp::Invalid(e.to_string()),
                };

                let resp = resp.to_json_vec()?;
                stream.write_u16(resp.len() as u16).await?;
                stream.write_all(&resp).await
            };

            if let Err(e) = fut.await {
                error!("{}", e)
            }
        });
    }
}

pub fn call(req: Req, dest: impl ToSocketAddrs) -> Result<()> {
    let mut stream = TcpStream::connect(dest)?;
    let req = req.to_json_vec()?;
    stream.write_all(&(req.len() as u16).to_be_bytes())?;
    stream.write_all(&req)?;

    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let mut data = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut data)?;

    let resp: Resp<HashMap<Ipv4Addr, Vec<NodeInfo>>> = serde_json::from_slice(&data)?;

    match resp {
        Resp::Success(map) => {
            println!("{:#?}", map);
            Ok(())
        }
        Resp::Invalid(_) => Err(anyhow!("Invalid command")),
        Resp::Error(_) => unreachable!(),
    }
}
