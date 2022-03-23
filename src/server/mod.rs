use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use parking_lot::RwLock;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, watch};
use tokio::{sync, time};

use crate::common::cipher::Aes128Ctr;
use crate::common::net::msg_operator::{TcpMsgReader, TcpMsgWriter, UdpMsgSocket, TCP_BUFF_SIZE};
use crate::common::net::proto::{HeartbeatType, MsgResult, Node, NodeId, TcpMsg, UdpMsg};
use crate::common::net::SocketExt;
use crate::common::{HashMap, MapInit, PointerWrap};
use crate::{Listener, ServerConfigFinalize};

static mut CONFIG: PointerWrap<ServerConfigFinalize> = PointerWrap::null();

fn set_config(config: ServerConfigFinalize) {
    unsafe { CONFIG = PointerWrap::new(Box::leak(Box::new(config))) }
}

fn get_config() -> &'static ServerConfigFinalize {
    unsafe { &*CONFIG }
}

struct NodeHandle {
    node: Node,
    tx: Sender<(Box<[u8]>, NodeId)>,
}

struct Bridge<'a> {
    node: Node,
    channel_rx: Receiver<(Box<[u8]>, NodeId)>,
    watch_rx: watch::Receiver<HashMap<NodeId, Node>>,
    node_db: &'a NodeDb,
}

struct NodeDb {
    mapping: RwLock<HashMap<NodeId, NodeHandle>>,
    watch: (
        watch::Sender<HashMap<NodeId, Node>>,
        watch::Receiver<HashMap<NodeId, Node>>,
    ),
}

impl Drop for Bridge<'_> {
    fn drop(&mut self) {
        let node_id = self.node.id;
        let register_time = self.node.register_time;

        let mut guard = self.node_db.mapping.write();

        if let Some(NodeHandle { node, .. }) = guard.get(&node_id) {
            if node.register_time == register_time {
                guard.remove(&node_id);
                drop(guard);

                if let Err(e) = self.node_db.sync() {
                    error!("Sync node db error: {:?}", e)
                }
            }
        };
    }
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
        let (tx, rx) = mpsc::channel::<(Box<[u8]>, NodeId)>(get_config().channel_limit);

        self.mapping.write().insert(
            node_id,
            NodeHandle {
                node: node.clone(),
                tx,
            },
        );
        self.sync()?;

        let bridge = Bridge {
            node,
            channel_rx: rx,
            watch_rx: watch_rx.clone(),
            node_db: self,
        };
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

        let node_list: HashMap<NodeId, Node> = self
            .mapping
            .read()
            .iter()
            .map(|(node_id, handle)| (*node_id, handle.node.clone()))
            .collect();

        tx.send(node_list).map_err(|_| anyhow!("Sync error"))?;
        Ok(())
    }
}

async fn udp_handler(listen_addr: SocketAddr, key: Aes128Ctr, node_db: Arc<NodeDb>) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("UDP socket bind {} error", listen_addr))?;

    info!("UDP socket listening on {}", listen_addr);

    let mut msg_socket = UdpMsgSocket::new(&socket, key);

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

                let res = node_db.get(&node_id, |v| match v {
                    Some(NodeHandle { node, .. }) => {
                        !matches!(node.wan_udp_addr, Some(addr) if addr == peer_addr)
                    }
                    None => false,
                });

                if !res {
                    continue;
                }

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

async fn tcp_handler(listen_addr: SocketAddr, key: Aes128Ctr, node_db: Arc<NodeDb>) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("TCP socket bind {} error", listen_addr))?;

    info!("TCP socket listening on {}", listen_addr);

    loop {
        let key = key.clone();
        let node_db = node_db.clone();
        let (stream, peer_addr) = listener.accept().await.context("Accept connection error")?;

        tokio::spawn(async move {
            if let Err(e) = tunnel(stream, key, node_db).await {
                error!("Peer addr {} tunnel error -> {:?}", peer_addr, e)
            }
        });
    }
}

async fn tunnel(mut stream: TcpStream, key: Aes128Ctr, node_db: Arc<NodeDb>) -> Result<()> {
    stream.set_keepalive()?;
    let (rx, mut tx) = stream.split();
    let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

    let mut rx_key = key.clone();
    let mut tx_key = key;

    let mut msg_reader = TcpMsgReader::new(&mut rx, &mut rx_key);
    let mut msg_writer = TcpMsgWriter::new(&mut tx, &mut tx_key);

    let msg = msg_reader.read().await?;
    let mut bridge = match msg {
        TcpMsg::Register(node) => {
            let register_time = node.register_time;
            let remain = Utc::now().timestamp() - register_time;

            if (remain > 10) || (remain < -10) {
                msg_writer
                    .write(&TcpMsg::Result(MsgResult::Timeout))
                    .await?;
                return Err(anyhow!("Register message timeout"));
            }

            msg_writer
                .write(&TcpMsg::Result(MsgResult::Success))
                .await?;
            node_db.insert(node)?
        }
        _ => return Err(anyhow!("Register error")),
    };

    let node_id = bridge.node.id;
    let inner_node_db = &*node_db;

    let (tx, mut rx) = sync::mpsc::unbounded_channel::<TcpMsg>();

    let latest_recv_heartbeat_time = AtomicI64::new(Utc::now().timestamp());
    let latest_recv_heartbeat_time_ref1 = &latest_recv_heartbeat_time;
    let latest_recv_heartbeat_time_ref2 = &latest_recv_heartbeat_time;

    let seq: AtomicU32 = AtomicU32::new(0);
    let inner_seq1 = &seq;
    let inner_seq2 = &seq;

    let fut1 = async move {
        loop {
            match msg_reader.read().await? {
                TcpMsg::Forward(data, dest_node_id) => {
                    inner_node_db.get(&dest_node_id, |op| {
                        if let Some(NodeHandle { tx: channel_tx, .. }) = op {
                            if let Err(TrySendError::Closed(_)) =
                                channel_tx.try_send((data.into(), node_id))
                            {
                                error!("Dest node {} channel closed", dest_node_id)
                            }
                        }
                    });
                }
                TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                    let heartbeat = TcpMsg::Heartbeat(seq, HeartbeatType::Resp);
                    tx.send(heartbeat).map_err(|e| anyhow!(e.to_string()))?;
                }
                TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                    if inner_seq1.load(Ordering::Relaxed) == recv_seq {
                        latest_recv_heartbeat_time_ref1
                            .store(Utc::now().timestamp(), Ordering::Relaxed)
                    }
                }
                _ => return Result::<()>::Err(anyhow!("Invalid TCP msg")),
            }
        }
    };

    let fut2 = async move {
        let mut heartbeat_interval = time::interval(get_config().tcp_heartbeat_interval);
        let mut check_heartbeat_timeout = time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                 opt = rx.recv() => {
                     match opt {
                        Some(heartbeat) => msg_writer.write(&heartbeat).await?,
                        None => return Ok(())
                    }
                }
                res = bridge.watch_rx.changed() => {
                    res?;
                    let node_list = bridge.watch_rx.borrow().clone();
                    let msg = TcpMsg::NodeMap(node_list);
                    msg_writer.write(&msg).await?;
                }
                res = bridge.channel_rx.recv() => {
                    let (data, node_id) = res.ok_or_else(|| anyhow!("Node {} channel closed", node_id))?;
                    let msg = TcpMsg::Forward(&data, node_id);
                    msg_writer.write(&msg).await?;
                }
                _ = heartbeat_interval.tick() => {
                    inner_seq2.fetch_add(1, Ordering::Relaxed);
                    let heartbeat = TcpMsg::Heartbeat(inner_seq2.load(Ordering::Relaxed), HeartbeatType::Req);
                    msg_writer.write(&heartbeat).await?;
                }
                _ = check_heartbeat_timeout.tick() => {
                     if Utc::now().timestamp() - latest_recv_heartbeat_time_ref2.load(Ordering::Relaxed) > 30 {
                        return Err(anyhow!("Heartbeat recv timeout"))
                    }
                }
            }
        }
    };

    tokio::try_join!(fut1, fut2)?;
    Ok(())
}

pub(super) async fn start(server_config: ServerConfigFinalize) {
    set_config(server_config);
    let mut list = Vec::with_capacity(get_config().listeners.len());

    for Listener { listen_addr, key } in &get_config().listeners {
        let handle = async move {
            let key = Aes128Ctr::new(key.as_bytes());
            let node_db = Arc::new(NodeDb::new());
            let key_ref = key.clone();
            let node_db_ref = node_db.clone();

            let udp_handle = async move {
                tokio::spawn(udp_handler(*listen_addr, key, node_db))
                    .await?
                    .context("UDP handler error")
            };

            let tcp_handle = async move {
                tokio::spawn(tcp_handler(*listen_addr, key_ref, node_db_ref))
                    .await?
                    .context("TCP handler error")
            };

            // TODO when error occurs in one handler, the other does not end
            if let Err(e) = tokio::try_join!(udp_handle, tcp_handle) {
                error!("Server {} execute error -> {:?}", listen_addr, e)
            };
        };
        list.push(handle);
    }

    futures_util::future::join_all(list).await;
}
