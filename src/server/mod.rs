use std::collections::HashMap;
use std::net::SocketAddr;

use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use tokio::io::{Error, ErrorKind, Result};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};

use crate::common::net::TcpSocketExt;
use crate::common::persistence::ToJson;
use crate::common::proto::{MsgReader, MsgSocket, MsgWriter, Node, NodeId};
use crate::common::proto::Msg;
use crate::common::res::StdResAutoConvert;

static MAPPING: Lazy<RwLock<HashMap<NodeId, Node>>> = Lazy::new(|| RwLock::new(HashMap::new()));

static BROADCAST: Lazy<(Sender<Vec<u8>>, Receiver<Vec<u8>>)> =
    Lazy::new(|| watch::channel::<Vec<u8>>(Vec::new()));

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
                let guard = MAPPING.read();

                if let Some(node) = guard.get(&node_id) {
                    if let Some(udp_addr) = node.source_udp_addr {
                        if udp_addr == peer_addr {
                            continue;
                        }
                    };

                    drop(guard);

                    let mut guard = MAPPING.write();

                    if let Some(node) = guard.get_mut(&node_id) {
                        node.source_udp_addr = Some(peer_addr);

                        let map = (*guard).clone();
                        drop(guard);
                        (*BROADCAST).0.send(map.to_json_vec()?).res_auto_convert()?;
                    }
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

    let (node_id, register_time) = match msg {
        Msg::Register(node) => {
            let node_id = node.id;
            let register_time = node.register_time;

            let mut guard = MAPPING.write();
            guard.insert(node_id, node);
            let map = (*guard).clone();

            drop(guard);
            (*BROADCAST).0.send(map.to_json_vec()?).res_auto_convert()?;
            (node_id, register_time)
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

    let mut guard = MAPPING.write();

    if let Some(node) = guard.get(&node_id) {
        if node.register_time == register_time {
            guard.remove(&node_id);

            let map = (*guard).clone();
            drop(guard);
            (*BROADCAST).0.send(map.to_json_vec()?).res_auto_convert()?;
        }
    }
    res
}

