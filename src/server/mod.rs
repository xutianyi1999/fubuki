use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use crypto::rc4::Rc4;
use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::common::net::msg_operator::{TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, Node, NodeId, TcpMsg, UdpMsg};
use crate::ServerConfig;

struct NodeHandle {
    node: Node,
    tx: Sender<(Box<[u8]>, NodeId)>,
}

struct Bridge {
    channel_rx: Receiver<(Box<[u8]>, NodeId)>,
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
            watch: watch::channel(vec![]),
        }
    }

    fn insert(&self, node: Node) -> Result<Bridge, Box<dyn Error>> {
        let node_id = node.id;
        let (_, watch_rx) = &self.watch;
        let (tx, rx) = mpsc::channel::<(Box<[u8]>, NodeId)>(10);

        self.mapping.write().insert(node_id, NodeHandle { node, tx });
        self.sync()?;

        let bridge = Bridge { channel_rx: rx, watch_rx: watch_rx.clone() };
        Ok(bridge)
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
        let (tx, _) = &self.watch;

        let node_list: Vec<Node> = self.mapping.read().iter()
            .map(|(_, handle)| handle.node.clone())
            .collect();

        tx.send(node_list)?;
        Ok(())
    }
}

pub(super) async fn start(server_config: Vec<ServerConfig>) {
    for ServerConfig { listen_addr, key } in server_config {
        tokio::spawn(async move {
            let rc4 = Rc4::new(key.as_bytes());
            let node_db = Arc::new(NodeDb::new());

            let res = tokio::select! {
                res = udp_handler(listen_addr, rc4, &node_db) => res,
                res = tcp_handler(listen_addr, rc4, &node_db) => res
            };

            if let Err(e) = res {
                error!("Server execute error -> {}", e)
            };
        });
    }
}

async fn udp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    node_db: &Arc<NodeDb>,
) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("UDP socket listening on {}", listen_addr);

    let mut msg_socket = UdpMsgSocket::new(&socket, rc4);

    loop {
        let (msg, peer_addr) = msg_socket.read().await?;

        if let UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req) = msg {
            let heartbeat = UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp);
            msg_socket.write(&heartbeat, peer_addr).await?;

            let res = node_db.get(&node_id, |v| {
                match v {
                    Some(NodeHandle { node, .. }) => {
                        match node.source_udp_addr {
                            Some(addr) if addr == peer_addr => false,
                            _ => true
                        }
                    }
                    None => false
                }
            });

            if !res { continue; }

            node_db.get_mut(&node_id, |v| {
                if let Some(NodeHandle { node, .. }) = v {
                    node.source_udp_addr = Some(peer_addr)
                }
            })?;
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

    let mut msg_reader = TcpMsgReader::new(&mut rx, &mut rx_rc4);
    let mut msg_writer = TcpMsgWriter::new(&mut tx, &mut tx_rc4);

    let msg = msg_reader.read().await?;

    let (
        node_id,
        register_time,
        Bridge {
            watch_rx: mut watch,
            mut channel_rx
        }
    ) = match msg {
        TcpMsg::Register(node) => {
            let node_id = node.id;
            let register_time = DateTime::<Utc>::from_str(&node.register_time)?;

            let remain = (Utc::now() - register_time).num_seconds();

            if (remain > 10) || (remain < -10) {
                msg_writer.write(&TcpMsg::Result(MsgResult::Timeout)).await?;
                return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "Register message timeout")));
            }

            msg_writer.write(&TcpMsg::Result(MsgResult::Success)).await?;

            let bridge = node_db.insert(node)?;
            (node_id, register_time, bridge)
        }
        _ => return Err(Box::new(io::Error::new(io::ErrorKind::InvalidData, "Register error")))
    };

    let inner_node_db = &node_db;

    let fut1 = async move {
        loop {
            let msg = msg_reader.read().await?;

            if let TcpMsg::Forward(data, node_id) = msg {
                inner_node_db.get(&node_id, |op| {
                    if let Some(NodeHandle { tx: channel_tx, .. }) = op {
                        if let Err(e) = channel_tx.try_send((data.into(), node_id)) {
                            error!("Node channel error -> {}", e)
                        }
                    }
                });
            }
        }
    };

    let fut2 = async move {
        loop {
            tokio::select! {
                res = watch.changed() => {
                    res?;
                    let node_list = watch.borrow().clone();
                    let msg = TcpMsg::NodeList(node_list);
                    msg_writer.write(&msg).await?;
                }
                res = channel_rx.recv() => {
                    let (data, node_id) = res.ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, "MPSC closed"))?;
                    let msg = TcpMsg::Forward(&data, node_id);
                    msg_writer.write(&msg).await?;
                }
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
