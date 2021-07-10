use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use crypto::rc4::Rc4;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};
use tokio::task;

use crate::common::net::TcpSocketExt;
use crate::common::persistence::ToJson;
use crate::common::proto::{MsgReader, MsgSocket, MsgWriter, Node, NodeId};
use crate::common::proto::Msg;

type Mapping = Rc<RefCell<HashMap<NodeId, Node>>>;
type Broadcast = (Rc<Sender<HashMap<NodeId, Node>>>, Receiver<HashMap<NodeId, Node>>);

pub async fn start(listen_addr: SocketAddr, rc4: Rc4) -> Result<(), Box<dyn Error>> {
    let mapping = Rc::new(RefCell::new(HashMap::new()));
    let (tx, rx) = watch::channel::<HashMap<NodeId, Node>>(HashMap::new());

    let tx = Rc::new(tx);
    let broadcast: Broadcast = (tx, rx);

    tokio::select! {
        res = udp_handler(listen_addr, rc4, &mapping, &broadcast.0) => res,
        res = tcp_handler(listen_addr, rc4, &mapping, &broadcast) => res
    }
}

async fn udp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    mapping: &Mapping,
    tx: &Rc<Sender<HashMap<NodeId, Node>>>,
) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("Udp socket listening on {}", listen_addr);

    let mut msg_socket = MsgSocket::new(&socket, rc4);

    loop {
        if let Ok((msg, peer_addr)) = msg_socket.recv_msg().await {
            if let Msg::Heartbeat(node_id) = msg {
                let mut guard = mapping.borrow_mut();

                if let Some(node) = guard.get_mut(&node_id) {
                    if let Some(udp_addr) = node.source_udp_addr {
                        if udp_addr == peer_addr {
                            continue;
                        }
                    };

                    node.source_udp_addr = Some(peer_addr);
                    tx.send(guard.clone())?;
                }
            }
        }
    };
}

async fn tcp_handler(
    listen_addr: SocketAddr,
    rc4: Rc4,
    mapping: &Mapping,
    broadcast: &Broadcast,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Tcp socket listening on {}", listen_addr);

    let local = task::LocalSet::new();

    local.run_until(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let inner_mapping = mapping.clone();
            let inner_broadcast = broadcast.clone();

            task::spawn_local(async move {
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
    }).await
}

async fn tunnel(
    mut stream: TcpStream,
    rc4: Rc4,
    mapping: Mapping,
    broadcast: Broadcast,
) -> Result<(), Box<dyn Error>> {
    stream.set_keepalive()?;
    let (rx, tx) = stream.split();

    let mut reader = MsgReader::new(rx, rc4);
    let mut writer = MsgWriter::new(tx, rc4);

    let op = reader.read_msg().await?;

    let msg = match op {
        Some(v) => v,
        None => return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Register error")))
    };

    let (node_id, register_time) = match msg {
        Msg::Register(node) => {
            let node_id = node.id;
            let register_time = node.register_time;

            let mut guard = mapping.borrow_mut();
            guard.insert(node_id, node);

            broadcast.0.send(guard.clone())?;
            (node_id, register_time)
        }
        _ => return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Register error")))
    };

    let f1 = async {
        let mut rx = broadcast.1.clone();

        while rx.changed().await.is_ok() {
            let vec = (*rx.borrow()).to_json_vec()?;
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

    let mut guard = mapping.borrow_mut();

    if let Some(node) = guard.get(&node_id) {
        if node.register_time == register_time {
            guard.remove(&node_id);
            broadcast.0.send(guard.clone())?;
        }
    }
    res
}

