use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use crypto::rc4::Rc4;
use parking_lot::RwLock;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::mpsc::error::TrySendError;
use tokio::time;

use crate::common::net::msg_operator::{TCP_BUFF_SIZE, TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, Node, NodeId, Seq, TcpMsg, UdpMsg};
use crate::common::net::TcpSocketExt;
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

    fn insert(&self, node: Node) -> Result<Bridge> {
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

    fn get_mut<R, F: FnOnce(Option<&mut NodeHandle>) -> R>(&self, id: &NodeId, f: F) -> Result<R> {
        let r = f(self.mapping.write().get_mut(id));
        self.sync()?;
        Ok(r)
    }

    fn sync(&self) -> Result<()> {
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
                res = udp_handler(listen_addr, rc4, &node_db) => res.context("UDP handler error"),
                res = tcp_handler(listen_addr, rc4, &node_db) => res.context("TCP handler error")
            };

            if let Err(e) = res {
                error!("Server execute error -> {:?}", e)
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
) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr).await.with_context(|| format!("UDP socket bind {} error", listen_addr))?;
    info!("UDP socket listening on {}", listen_addr);

    let mut msg_socket = UdpMsgSocket::new(&socket, rc4);

    loop {
        let msg = match msg_socket.read().await {
            Ok(v) => v,
            Err(e) => {
                error!("UDP msg read error -> {:?}", e);
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
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await.with_context(|| format!("TCP socket bind {} error", listen_addr))?;
    info!("TCP socket listening on {}", listen_addr);

    loop {
        let node_db = node_db.clone();
        let (stream, peer_addr) = listener.accept().await.context("Accept connection error")?;

        tokio::spawn(async move {
            if let Err(e) = tunnel(stream, rc4, node_db).await {
                error!("Peer addr {} tunnel error -> {:?}", peer_addr, e)
            }
        });
    }
}

async fn tunnel(
    mut stream: TcpStream,
    rc4: Rc4,
    node_db: Arc<NodeDb>,
) -> Result<()> {
    stream.set_keepalive()?;
    let (rx, mut tx) = stream.split();
    let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

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
                return Err(anyhow!("Register message timeout"));
            }

            msg_writer.write(&TcpMsg::Result(MsgResult::Success)).await?;

            let bridge = node_db.insert(node)?;
            (node_id, register_time, bridge)
        }
        _ => return Err(anyhow!("Register error"))
    };

    let inner_node_db = &node_db;

    let res = async move {
        let mut latest_recv_heartbeat_time = Instant::now();
        let mut heartbeat_interval = time::interval(Duration::from_secs(5));
        let mut check_heartbeat_timeout = time::interval(Duration::from_secs(30));

        let mut seq: Seq = 0;

        loop {
            tokio::select! {
                res = watch.changed() => {
                    res?;
                    let node_list = watch.borrow().clone();
                    let msg = TcpMsg::NodeMap(node_list);
                    msg_writer.write(&msg).await?;
                }
                res = channel_rx.recv() => {
                    let (data, node_id) = res.ok_or(anyhow!("Node {} channel closed", node_id))?;
                    let msg = TcpMsg::Forward(&data, node_id);
                    msg_writer.write(&msg).await?;
                }
                res = msg_reader.read() => {
                    match res? {
                       TcpMsg::Forward(data, dest_node_id) => {
                            inner_node_db.get(&dest_node_id, |op| {
                                if let Some(NodeHandle { tx: channel_tx, .. }) = op {
                                    if let Err(TrySendError::Closed(_)) = channel_tx.try_send((data.into(), node_id)) {
                                        error!("Dest node {} channel closed", dest_node_id)
                                    }
                                }
                            });
                        }
                        TcpMsg::Heartbeat(node_id, seq, HeartbeatType::Req) => {
                            let heartbeat = TcpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp);
                            msg_writer.write(&heartbeat).await?;
                        }
                        TcpMsg::Heartbeat(_, recv_seq, HeartbeatType::Resp) => {
                            if seq == recv_seq {
                                latest_recv_heartbeat_time = Instant::now();
                            }
                        }
                        _ => return Err(anyhow!("Invalid TCP msg"))
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if seq == Seq::MAX {
                        seq = 0;
                    } else {
                        seq += 1;
                    }

                    let heartbeat = TcpMsg::Heartbeat(node_id, seq, HeartbeatType::Req);
                    msg_writer.write(&heartbeat).await?;
                }
                _ = check_heartbeat_timeout.tick() => {
                    if latest_recv_heartbeat_time.elapsed() >= Duration::from_secs(30) {
                        return Err(anyhow!("Heartbeat recv timeout"))
                    }
                }
            }
        }
    }.await;

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
