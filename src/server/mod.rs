use std::borrow::BorrowMut;
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
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::Instant;

use crate::common::persistence::ToJson;
use crate::common::proto;
use crate::common::proto::{HeartbeatType, Node, NodeId, TcpMsg, UdpMsg};

struct NodeHandle {
    node: Node,
    tx: Sender<Box<[u8]>>,
}

struct Bridge {
    channel_rx: Receiver<Box<[u8]>>,
    watch_rx: watch::Receiver<Box<[u8]>>,
}

struct NodeDb {
    mapping: RwLock<HashMap<NodeId, NodeHandle>>,
    watch: (watch::Sender<Box<[u8]>>, watch::Receiver<Box<[u8]>>),
}

impl NodeDb {
    fn new() -> Self {
        NodeDb {
            mapping: RwLock::new(HashMap::new()),
            watch: watch::channel(Box::from([0u8; 0])),
        }
    }

    fn insert(&self, node: Node) -> Result<Bridge, Box<dyn Error>> {
        let node_id = node.id;
        let (tx, rx) = mpsc::channel::<Box<[u8]>>(10);

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

        let mut buff = vec![0u8; 65535];
        let data = TcpMsg::NodeList(node_list).encode(&mut buff)?;

        self.watch.0.send(data.into())?;
        Ok(())
    }
}

async fn start(listen_addr: SocketAddr, rc4: Rc4) -> Result<(), Box<dyn Error>> {
    let node_db = Arc::new(NodeDb::new());

    tokio::select! {
        res = udp_handler(listen_addr, rc4, &node_db) => res,
        res = tcp_handler(listen_addr, rc4, &node_db) => res
    }
}

async fn udp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    node_db: &Arc<NodeDb>,
) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("UDP socket listening on {}", listen_addr);

    let mut buff = [0u8; 1024];
    let mut out = [0u8; 1024];

    loop {
        let mut inner_rc4 = rc4;
        let (len, peer_addr) = socket.recv_from(&mut buff).await?;
        let packet = &buff[..len];
        let packet = proto::crypto(packet, &mut out, &mut inner_rc4)?;

        if let Ok(UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req)) = UdpMsg::decode(packet) {
            socket.send_to(
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp).encode(&mut buff)?,
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
    node_db: &Arc<NodeDb>,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("TCP socket listening on {}", listen_addr);

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
    let (mut rx, mut tx) = stream.split();

    let mut rx_rc4 = rc4;
    let mut tx_rc4 = rc4;

    let len = rx.read_u16().await? as usize;
    let mut buff = vec![0u8; len];
    rx.read_exact(&mut buff).await?;

    let mut buff2 = vec![0u8; len];
    let packet = proto::crypto(&mut buff, &mut buff2, &mut rx_rc4)?;

    let (
        node_id,
        register_time,
        Bridge { watch_rx: mut watch, mut channel_rx }
    ) = match TcpMsg::decode(packet)? {
        TcpMsg::Register(node) => {
            let node_id = node.id;
            let register_time = DateTime::<Utc>::from_str(&node.register_time)?;

            let remain = (Utc::now() - register_time).num_seconds();

            if (remain > 10) || (remain < -10) {
                return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "Register message timeout")));
            }

            let bridge = node_db.insert(node)?;
            (node_id, register_time, bridge)
        }
        _ => return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "Register error")))
    };

    let inner_node_db = &node_db;

    let fut1 = async move {
        let mut buff = vec![0u8; 65535];
        let mut out = vec![0u8; 65535];

        loop {
            let len = rx.read_u16().await?;
            let slice = &mut buff[..len as usize];
            rx.read_exact(slice).await?;

            let packet = proto::crypto(slice, &mut out, &mut rx_rc4)?;

            if let TcpMsg::Forward(data, node_id) = TcpMsg::decode(packet)? {
                inner_node_db.get(&node_id, |op| {
                    match op {
                        Some(NodeHandle { tx: channel_tx, .. }) => {
                            channel_tx.try_send(packet.into());
                        }
                        _ => ()
                    }
                });
            }
        }
    };

    let fut2 = async move {
        let mut buff = vec![0u8; 65535];
        let mut out = vec![0u8; 65535];

        loop {
            tokio::select! {
                res = watch.changed() => {
                    res?;
                    node_list_sync(&watch, &mut tx, &mut tx_rc4, &mut buff, &mut out).await?;
                }
                res = channel_rx.recv() => mpsc_to_socket(res, &mut tx, &mut tx_rc4, &mut buff, &mut out).await?
            }
        }
    };

    let res = tokio::select! {
        res = fut1 => res,
        res = fut2 => res
    };

    let mut guard = node_db.mapping.write();

    if let Some(NodeHandle { node, .. }) = guard.get(&node_id) {
        if DateTime::<Utc>::from_str(&node.register_time)? == register_time {
            guard.remove(&node_id);
            drop(guard);
            node_db.sync()?;
        }
    };
    res
}

async fn node_list_sync<TX: AsyncWrite + Unpin>(
    watch: &watch::Receiver<Box<[u8]>>,
    tx: &mut TX,
    rc4: &mut Rc4,
    buff: &mut [u8],
    out: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let node_list = watch.borrow().clone();
    let packet = proto::crypto(&node_list, buff, rc4)?;
    let len = packet.len();

    out[..2].copy_from_slice(&(len as u16).to_be_bytes());
    out[2..len + 2].copy_from_slice(packet);

    tx.write_all(&out[..len + 2]).await?;
    Ok(())
}

async fn mpsc_to_socket<TX: AsyncWrite + Unpin>(
    data: Option<Box<[u8]>>,
    tx: &mut TX,
    rc4: &mut Rc4,
    buff: &mut [u8],
    out: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let data = data.ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, "MPSC closed"))?;
    let packet = proto::crypto(&data, buff, rc4)?;
    let len = packet.len();

    out[..2].copy_from_slice(&(len as u16).to_be_bytes());
    out[2..len + 2].copy_from_slice(packet);

    tx.write_all(&out[..len + 2]).await?;
    Ok(())
}

