use std::net::SocketAddr;

use crypto::rc4::Rc4;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use tokio::io::{Error, ErrorKind, Result};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};

use crate::common::net::TcpSocketExt;
use crate::common::persistence::ToJson;
use crate::common::proto::{MsgReader, MsgSocket, MsgWriter, Node, NodeId};
use crate::common::proto::Msg;
use crate::common::res::StdResAutoConvert;

static MAPPING: Lazy<NatMapping> = Lazy::new(|| NatMapping::new());
static BROADCAST: Lazy<(Sender<Vec<u8>>, Receiver<Vec<u8>>)> =
    Lazy::new(|| watch::channel::<Vec<u8>>(Vec::new()));

struct NatMapping {
    map: DashMap<NodeId, Node>
}

impl NatMapping {
    fn new() -> Self {
        NatMapping { map: DashMap::new() }
    }

    fn get(&self, id: &NodeId) -> Option<Node> {
        let op = self.map.get(id);
        op.map(|v| v.clone())
    }

    fn insert(&self, id: NodeId, node: Node) -> () {
        self.map.insert(id, node);
        self.config_broadcast().unwrap();
    }

    fn update<F>(&self, id: &NodeId, f: F) -> ()
        where F: FnOnce(&u32, Node) -> Node
    {
        self.map.alter(id, f);
        self.config_broadcast().unwrap();
    }

    fn remove(&self, id: &NodeId) -> Option<Node> {
        let op = self.map.remove(id).map(|v| v.1);
        self.config_broadcast().unwrap();
        op
    }

    fn get_all(&self) -> DashMap<NodeId, Node> {
        self.map.clone()
    }

    fn config_broadcast(&self) -> Result<()> {
        let map = self.get_all();
        let json_vec = map.to_json_vec()?;
        (*BROADCAST).0.send(json_vec).res_auto_convert()
    }
}

pub async fn start(listen_addr: SocketAddr, rc4: Rc4) -> Result<()> {
    tokio::select! {
        res = udp_handle(listen_addr, rc4) => res,
        res = tcp_handle(listen_addr, rc4) => res
    }
}

async fn udp_handle(listen_addr: SocketAddr, rc4: Rc4) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("Udp socket listening on {}", listen_addr);

    let mut msg_socket = MsgSocket::new(&socket, rc4);

    loop {
        if let Ok((msg, peer_addr)) = msg_socket.recv_msg().await {
            if let Msg::Heartbeat(node_id) = msg {
                if let Some(node) = MAPPING.get(&node_id) {
                    if let Some(udp_addr) = node.source_udp_addr {
                        if udp_addr == peer_addr {
                            continue;
                        }
                    };

                    MAPPING.update(&node_id, |_, mut node| {
                        node.source_udp_addr = Some(peer_addr);
                        node
                    });
                }
            }
        }
    };
}

async fn tcp_handle(listen_addr: SocketAddr, rc4: Rc4) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Tcp socket listening on {}", listen_addr);

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = tunnel(stream, rc4).await {
                    error!("tunnel error -> {}", e)
                }
            });
        };
    }
}

async fn tunnel(mut stream: TcpStream, rc4: Rc4) -> Result<()> {
    stream.set_keepalive()?;
    let (rx, tx) = stream.split();

    let mut reader = MsgReader::new(rx, rc4);
    let mut writer = MsgWriter::new(tx, rc4);

    let op = reader.read_msg().await?;

    let msg = match op {
        Some(v) => v,
        None => return Err(Error::new(ErrorKind::Other, "Register error"))
    };

    let node_id = match msg {
        Msg::Register(node) => {
            let node_id = node.id;
            MAPPING.insert(node_id, node);
            node_id
        }
        _ => return Err(Error::new(ErrorKind::Other, "Register error"))
    };

    let f1 = async move {
        let mut rx = (*BROADCAST).1.clone();

        while rx.changed().await.is_ok() {
            let vec = rx.borrow().clone();
            let msg = Msg::NodeMapSerde(&vec);
            writer.write_msg(msg).await?;
        }
        Ok(())
    };

    let f2 = async move {
        reader.read_msg().await?;
        Ok(())
    };

    let res = tokio::select! {
        res = f1 => res,
        res = f2 => res,
    };

    MAPPING.remove(&node_id);
    res
}

