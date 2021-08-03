use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crypto::rc4::Rc4;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::net::tcp::WriteHalf;
use tokio::sync::{mpsc, TryAcquireError, watch};
use tokio::sync;
use tokio::sync::mpsc::error::{SendTimeoutError, TrySendError};
use tokio::sync::watch::{Receiver, Sender};
use tokio::task;

use crate::common::net::TcpSocketExt;
use crate::common::proto::{MsgReader, MsgSocket, MsgWriter, Node, NodeId};
use crate::common::proto::Msg;

type Mapping = HashMap<NodeId, (Node, mpsc::Sender<Box<[u8]>>)>;
type SharedMapping = Arc<parking_lot::RwLock<Mapping>>;
type Broadcast = (Arc<Sender<HashMap<NodeId, Node>>>, Receiver<HashMap<NodeId, Node>>);

pub async fn start(listen_addr: SocketAddr, rc4: Rc4) -> Result<(), Box<dyn Error>> {
    let mapping: SharedMapping = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let (tx, rx) = watch::channel::<HashMap<NodeId, Node>>(HashMap::new());

    let tx = Arc::new(tx);
    let broadcast: Broadcast = (tx, rx);

    tokio::select! {
        res = udp_handler(listen_addr, rc4, &mapping, &broadcast.0) => res,
        res = tcp_handler(listen_addr, rc4, &mapping, &broadcast) => res
    }
}

async fn udp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    mapping: &SharedMapping,
    tx: &Arc<Sender<HashMap<NodeId, Node>>>,
) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("Udp socket listening on {}", listen_addr);

    let mut msg_socket = MsgSocket::new(&socket, rc4);

    loop {
        if let Ok((msg, peer_addr)) = msg_socket.recv_msg().await {
            if let Msg::Heartbeat(node_id, _, _) = msg {
                let read_guard = mapping.read();

                match read_guard.get(&node_id) {
                    Some((node, _)) => {
                        if let Some(udp_addr) = node.source_udp_addr {
                            if udp_addr == peer_addr {
                                continue;
                            }
                        };
                    }
                    None => continue
                }

                drop(read_guard);
                let mut write_guard = mapping.write();

                if let Some((node, _)) = write_guard.get_mut(&node_id) {
                    node.source_udp_addr = Some(peer_addr);

                    let mapping: HashMap<NodeId, Node> = write_guard.iter()
                        .map(|(k, (node, _))| (*k, node.clone()))
                        .collect();

                    tx.send(mapping)?;
                }
            }
        }
    };
}

async fn tcp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    mapping: &SharedMapping,
    broadcast: &Broadcast,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Tcp socket listening on {}", listen_addr);

    while let Ok((stream, _)) = listener.accept().await {
        let inner_mapping = mapping.clone();
        let inner_broadcast = broadcast.clone();

        tokio::spawn(async move {
            if let Err(e) = tunnel(
                stream,
                rc4,
                inner_mapping,
                inner_broadcast,
            ).await {
                error!("Tunnel error -> {}", e)
            }
        });
    };
    Ok(())
}

async fn tunnel(
    mut stream: TcpStream,
    rc4: Rc4,
    shared_mapping: SharedMapping,
    (broadcast_tx, mut broadcast_rx): Broadcast,
) -> Result<(), Box<dyn Error>> {
    let mapping = &shared_mapping;
    stream.set_keepalive()?;
    let (rx, tx) = stream.split();

    let mut reader = MsgReader::new(rx, rc4);
    let mut writer = MsgWriter::new(tx, rc4);

    let op = reader.read_msg().await?;

    let msg = match op {
        Some(v) => v,
        None => return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Register error")))
    };

    let (node_id, register_time, mut mpsc_rx) = match msg {
        Msg::Register(node) => {
            let node_id = node.id;
            let register_time = node.register_time;

            let (mpsc_tx, mpsc_rx) = mpsc::channel::<Box<[u8]>>(100);
            let mut guard = mapping.write();
            guard.insert(node_id, (node, mpsc_tx));

            let mapping: HashMap<NodeId, Node> = guard.iter()
                .map(|(k, (node, _))| (*k, node.clone()))
                .collect();

            broadcast_tx.send(mapping)?;
            (node_id, register_time, mpsc_rx)
        }
        _ => return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Register error")))
    };

    let task = async move {
        loop {
            tokio::select! {
                res = broadcast_rx.changed() => {
                    res?;
                    mapping_sync(&broadcast_rx, &mut writer).await?
                }
                data = mpsc_rx.recv() => mpsc_to_socket(data, &mut writer).await?,
                data = reader.read_msg() => socket_to_mpsc(data, mapping)?
            }
        }
    };

    let res = task.await;
    let mut guard = mapping.write();

    if let Some((node, _)) = guard.get(&node_id) {
        if node.register_time == register_time {
            guard.remove(&node_id);
            let mapping: HashMap<NodeId, Node> = guard.iter()
                .map(|(k, (node, _))| (*k, node.clone()))
                .collect();

            broadcast_tx.send(mapping)?;
        }
    }
    res
}

async fn mapping_sync(
    broadcast: &Receiver<HashMap<NodeId, Node>>,
    tx: &mut MsgWriter<WriteHalf<'_>>,
) -> io::Result<()> {
    let map = broadcast.borrow().clone();
    tx.write_msg(Msg::NodeMap(map)).await
}

async fn mpsc_to_socket(
    data: Option<Box<[u8]>>,
    tx: &mut MsgWriter<WriteHalf<'_>>,
) -> io::Result<()> {
    let packet = data.ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, "MPSC closed"))?;
    tx.write_msg(Msg::Data(&packet)).await
}

fn socket_to_mpsc(
    data: io::Result<Option<Msg<'_>>>,
    mapping: &SharedMapping,
) -> io::Result<()> {
    if let Some(Msg::Forward(packet, node_id)) = data? {
        let guard = mapping.read();

        if let Some((_, tx)) = guard.get(&node_id) {
            tx.try_send(packet.into());
        }
    }
    Ok(())
}