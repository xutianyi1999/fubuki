use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use crypto::rc4::Rc4;
use parking_lot::RwLock;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;

use crate::common::persistence::ToJson;
use crate::common::proto::{HeartbeatType, Node, NodeId, TcpMsg, TcpMsgDecoder, TcpMsgEncoder, UdpMsg, UdpMsgCodec};

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    listen_addr: SocketAddr,
    key: String,
    forward_only: Option<bool>,
}

struct NodeHandle {
    node: Node,
    tx: Sender<TcpMsg>,
}

struct Bridge {
    channel_rx: Receiver<TcpMsg>,
    watch_rx: watch::Receiver<Vec<Node>>,
}

struct NodeDb {
    mapping: RwLock<HashMap<NodeId, NodeHandle>>,
    watch: (watch::Sender<Vec<Node>>, watch::Receiver<Vec<Node>>),
}

impl NodeDb {
    fn new() -> Self {
        NodeDb {
            mapping: RwLock::new(HashMap::new()),
            watch: watch::channel(Vec::new()),
        }
    }

    fn insert(&self, node: Node) -> Result<Bridge, Box<dyn Error>> {
        let node_id = node.id;
        let (tx, rx) = mpsc::channel::<TcpMsg>(30);

        self.mapping.write().insert(node_id, NodeHandle { node, tx });
        self.sync()?;

        let bridge = Bridge { channel_rx: rx, watch_rx: self.watch.1.clone() };
        Ok(bridge)
    }

    fn remove(&self, id: &NodeId) -> Result<Option<NodeHandle>, Box<dyn Error>> {
        let op = self.mapping.write().remove(id);
        self.sync()?;
        Ok(op)
    }

    fn get<R, F: FnOnce(Option<&NodeHandle>) -> R>(&self, id: &NodeId, f: F) -> R {
        f(self.mapping.read().get(id))
    }

    fn get_mut<R, F: FnOnce(Option<&mut NodeHandle>) -> R>(&self, id: &NodeId, f: F) -> Result<R, Box<dyn Error>> {
        let r = f(self.mapping.write().get_mut(id));
        self.sync()?;
        Ok(r)
    }

    fn sync(&self) -> Result<(), Box<dyn Error>> {
        let node_list: Vec<Node> = self.mapping.read().iter()
            .map(|(_, handle)| handle.node.clone())
            .collect();

        self.watch.0.send(node_list)?;
        Ok(())
    }
}

async fn start(listen_addr: SocketAddr, rc4: Rc4) -> () {
    let node_db = Arc::new(NodeDb::new());
}

async fn udp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    node_db: Arc<NodeDb>,
) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("Udp socket listening on {}", listen_addr);

    let mut buff = [0u8; 1024];
    let mut codec = UdpMsgCodec::new(rc4);

    loop {
        let (len, peer_addr) = socket.recv_from(&mut buff).await?;

        if let Ok(UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req)) = codec.decode(&buff[..len]) {
            socket.send_to(
                codec.encode(UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp), &mut buff)?,
                peer_addr,
            ).await?;

            let res = node_db.get(&node_id, |v| {
                match v {
                    Some(node_handle) => {
                        match node_handle.node.source_udp_addr {
                            Some(addr) if addr == peer_addr => false,
                            _ => true
                        }
                    }
                    None => false
                }
            });

            if !res { continue; }

            node_db.get_mut(&node_id, |v| {
                if let Some(node_handle) = v {
                    node_handle.node.source_udp_addr = Some(peer_addr)
                }
            });
        }
    }
}

async fn tcp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    node_db: Arc<NodeDb>,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Tcp socket listening on {}", listen_addr);

    loop {
        let node_db = node_db.clone();
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = tunnel(stream, rc4, node_db).await {
                error!("Tunnel error -> {}", e)
            }
        });
    }
}

async fn tunnel(
    mut stream: TcpStream,
    rc4: Rc4,
    node_db: Arc<NodeDb>,
) -> Result<(), Box<dyn Error>> {
    let mut decoder = TcpMsgDecoder::new(rc4);
    let mut encoder = TcpMsgEncoder::new(rc4);
    let mut buff = vec![0u8; 65536];

    let len = stream.read_u16().await?;
    let packet = &mut buff[..len as usize];

    stream.read_exact(packet).await?;

    let (node_id, register_time, bridge) = match decoder.decode(packet)? {
        TcpMsg::Register(node) => {
            let node_id = node.id;
            let register_time = node.register_time.clone();

            let bridge = node_db.insert(node)?;
            (node_id, register_time, bridge)
        }
        _ => return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Register error")))
    };

    let mut watch = bridge.watch_rx;
    let channel_rx = bridge.channel_rx;

    let mut a = 10;
    let p = &mut a;

    loop {
        // tokio::select! {
        //     res = watch.changed() => {
        //         res?;
        //
        //     }
        // }
    }
    Ok(())
}

async fn node_list_sync(
    watch: &watch::Receiver<Vec<Node>>,
    stream: &mut TcpStream,
    encoder: &mut TcpMsgEncoder,
) -> Result<(), Box<dyn Error>> {
    let node_list = watch.borrow().clone();
}

