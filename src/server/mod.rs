use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Utc;
use crypto::rc4::Rc4;
use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::mpsc::error::TrySendError;

use crate::common::net::msg_operator::{TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, Node, NodeId, TcpMsg, UdpMsg};
use crate::ServerConfig;

const CHANNEL_SIZE: usize = 10;

struct NodeHandle {
    node: Node,
    tx: Sender<(Box<[u8]>, NodeId)>,
}

struct Bridge {
    channel_rx: Receiver<(Box<[u8]>, NodeId)>,
    watch_rx: watch::Receiver<HashMap<NodeId, Node>>,
}

struct NodeDb {
    mapping: RwLock<HashMap<NodeId, NodeHandle>>,
    watch: (watch::Sender<HashMap<NodeId, Node>>, watch::Receiver<HashMap<NodeId, Node>>),
}

impl NodeDb {
    fn new() -> Self {
        NodeDb {
            mapping: RwLock::new(HashMap::new()),
            watch: watch::channel(HashMap::new()),
        }
    }

    fn insert(&self, node: Node) -> Result<Bridge, Box<dyn Error>> {
        let node_id = node.id;
        let (_, watch_rx) = &self.watch;
        let (tx, rx) = mpsc::channel::<(Box<[u8]>, NodeId)>(CHANNEL_SIZE);

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

        let node_list: HashMap<NodeId, Node> = self.mapping.read().iter()
            .map(|(node_id, handle)| (*node_id, handle.node.clone()))
            .collect();

        tx.send(node_list)?;
        Ok(())
    }
}

pub(super) async fn start(server_config: Vec<ServerConfig>) {
    let mut list = Vec::with_capacity(server_config.len());

    for ServerConfig { listen_addr, key } in server_config {
        let future = async move {
            let rc4 = Rc4::new(key.as_bytes());
            let node_db = Arc::new(NodeDb::new());

            let res = tokio::select! {
                res = udp_handler(listen_addr, rc4, &node_db) => res,
                res = tcp_handler(listen_addr, rc4, &node_db) => res
            };

            if let Err(e) = res {
                error!("Server execute error -> {}", e)
            };
        };
        list.push(future);
    }
    futures_util::future::join_all(list).await;
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
        let msg = match msg_socket.read().await {
            Ok(v) => v,
            Err(e) => {
                error!("UDP msg read error -> {}", e);
                continue;
            }
        };

        match msg {
            (UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req), peer_addr) => {
                let heartbeat = UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp);
                msg_socket.write(&heartbeat, peer_addr).await?;

                let res = node_db.get(&node_id, |v| {
                    match v {
                        Some(NodeHandle { node, .. }) => {
                            match node.wan_udp_addr {
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
                        node.wan_udp_addr = Some(peer_addr)
                    }
                })?;
            }
            _ => error!("Invalid UDP msg"),
        };
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
        let (stream, peer_addr) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = tunnel(stream, rc4, node_db).await {
                error!("{:?} tunnel error -> {}", peer_addr, e)
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
            let register_time = node.register_time;

            let remain = Utc::now().timestamp() - register_time;

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
            match msg_reader.read().await? {
                TcpMsg::Forward(data, dest_node_id) => {
                    inner_node_db.get(&dest_node_id, |op| {
                        if let Some(NodeHandle { tx: channel_tx, .. }) = op {
                            if let Err(TrySendError::Closed(_)) = channel_tx.try_send((data.into(), node_id)) {
                                error!("Channel closed")
                            }
                        }
                    });
                }
                _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid TCP msg"))?
            };
        }
    };

    let fut2 = async move {
        loop {
            tokio::select! {
                res = watch.changed() => {
                    res?;
                    let node_list = watch.borrow().clone();
                    let msg = TcpMsg::NodeMap(node_list);
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
        if node.register_time == register_time {
            guard.remove(&node_id);
            drop(guard);
            node_db.sync()?;
        }
    };
    res
}
