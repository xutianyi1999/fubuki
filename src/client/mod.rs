use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, NaiveDateTime, Utc};
use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::Serialize;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time;

use crate::{ClientConfig, TunAdapter};
use crate::common::net::get_interface_addr;
use crate::common::net::msg_operator::{TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, MTU, Node, NodeId, TcpMsg, UdpMsg};
use crate::common::net::proto::UdpMsg::Heartbeat;
use crate::common::persistence::ToJson;
use crate::tun::{create_device, Rx, Tx};

static MAPPING: Lazy<LocalMapping> = Lazy::new(|| LocalMapping::new());
static DIRECT_NODE_LIST: Lazy<DirectNodeList> = Lazy::new(|| DirectNodeList::new());
static LOCAL_NODE: Lazy<RwLock<Node>> = Lazy::new(|| RwLock::new(
    Node { id: 0, tun_addr: Ipv4Addr::from([0, 0, 0, 0]), lan_udp_addr: None, wan_udp_addr: None, register_time: 0 }
));

struct DirectNodeList {
    list: RwLock<HashMap<NodeId, Instant>>,
}

impl DirectNodeList {
    fn new() -> Self {
        DirectNodeList { list: RwLock::new(HashMap::new()) }
    }

    fn contain(&self, node_id: &NodeId) -> bool {
        self.list.read().contains_key(node_id)
    }

    fn update(&self, node_id: NodeId) {
        let mut guard = self.list.write();
        guard.insert(node_id, Instant::now());
    }
}

// tun_addr -> node
struct LocalMapping {
    map: RwLock<HashMap<Ipv4Addr, Node>>,
}

impl LocalMapping {
    fn new() -> Self {
        LocalMapping { map: RwLock::new(HashMap::new()) }
    }

    fn get_all(&self) -> HashMap<Ipv4Addr, Node> {
        (*self.map.read()).clone()
    }

    fn update_all(&self, map: HashMap<Ipv4Addr, Node>) {
        *self.map.write() = map
    }
}

pub(super) async fn start(
    ClientConfig {
        server_addr,
        tun: TunAdapter {
            ip: tun_addr,
            netmask: tun_netmask
        },
        key,
        direct,
    }: ClientConfig
) -> Result<(), Box<dyn Error>> {
    let rc4 = Rc4::new(key.as_bytes());
    let node_id: NodeId = rand::random();
    let device = create_device(tun_addr, tun_netmask)?;
    let (tun_tx, tun_rx) = device.split();

    let (to_tun, from_handler) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (to_tcp_handler, from_tun2) = mpsc::channel::<(Box<[u8]>, NodeId)>(10);

    let mut node = Node {
        id: node_id,
        tun_addr,
        lan_udp_addr: None,
        wan_udp_addr: None,
        register_time: 0,
    };

    info!("Tun adapter ip address: {}", tun_addr);
    info!("Client start");

    tokio::task::spawn_blocking(move || if let Err(e) = stdin(node_id) { error!("{}", e) });

    if direct {
        let lan_ip = get_interface_addr(server_addr).await?;
        let udp_socket = UdpSocket::bind((lan_ip, 0)).await?;
        let (to_udp_handler, from_tun1) = mpsc::channel::<(Box<[u8]>, SocketAddr)>(10);

        node.lan_udp_addr = Some(udp_socket.local_addr()?);
        *LOCAL_NODE.write() = node;

        tokio::select! {
            res = direct_node_list_schedule() => res?,
            res = mpsc_to_tun(from_handler, tun_tx) => res??,
            res = tun_to_mpsc(to_tcp_handler, Some(to_udp_handler), tun_rx) => res??,
            res = udp_handler(udp_socket, from_tun1, to_tun.clone(), server_addr, rc4) => res?,
            res = tcp_handler(from_tun2, to_tun, server_addr, rc4) => res?,
        }
    } else {
        *LOCAL_NODE.write() = node;

        tokio::select! {
            res = mpsc_to_tun(from_handler, tun_tx) => res??,
            res = tun_to_mpsc(to_tcp_handler, None, tun_rx) => res??,
            res = tcp_handler(from_tun2, to_tun, server_addr, rc4) => res?,
        }
    };

    Ok(())
}

fn direct_node_list_schedule() -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            {
                let map = DIRECT_NODE_LIST.list.read().clone();

                let expire_node_id_list: Vec<NodeId> = map.into_iter()
                    .filter(|(_, update_time)| update_time.elapsed() > Duration::from_secs(30))
                    .map(|(node_id, _)| node_id)
                    .collect();

                let mut writer_guard = DIRECT_NODE_LIST.list.write();

                for node_id in expire_node_id_list {
                    writer_guard.remove(&node_id);
                }
            }

            time::sleep(Duration::from_secs(30)).await;
        }
    })
}

fn mpsc_to_tun(
    mut mpsc_rx: UnboundedReceiver<Box<[u8]>>,
    mut tun_tx: Box<dyn Tx>,
) -> JoinHandle<io::Result<()>> {
    tokio::task::spawn_blocking(move || {
        while let Some(packet) = mpsc_rx.blocking_recv() {
            tun_tx.send_packet(&packet)?;
        };
        Ok(())
    })
}

fn tun_to_mpsc(
    tcp_handler_tx: Sender<(Box<[u8]>, NodeId)>,
    udp_handler_tx_opt: Option<Sender<(Box<[u8]>, SocketAddr)>>,
    mut tun_rx: Box<dyn Rx>,
) -> JoinHandle<io::Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut buff = [0u8; MTU];

        loop {
            let data = match tun_rx.recv_packet(&mut buff)? {
                0 => continue,
                len => &buff[..len]
            };

            let ipv4 = Ipv4Packet::new_unchecked(data);
            let Ipv4Address(octets) = ipv4.dst_addr();
            let peer_tun_addr = Ipv4Addr::from(octets);

            let guard = MAPPING.map.read();
            let node_opt = guard.get(&peer_tun_addr);

            match (node_opt, &udp_handler_tx_opt) {
                (
                    Some(
                        Node {
                            id: node_id,
                            wan_udp_addr: Some(peer_wan_addr),
                            lan_udp_addr: Some(peer_lan_addr),
                            ..
                        }
                    ),
                    Some(udp_handler_tx)
                ) if DIRECT_NODE_LIST.contain(node_id) => {
                    let dest_addr = match LOCAL_NODE.read().wan_udp_addr {
                        Some(local_wan_addr) if local_wan_addr.ip() == peer_wan_addr.ip() => {
                            *peer_lan_addr
                        }
                        _ => *peer_wan_addr
                    };

                    if let Err(TrySendError::Closed(_)) = udp_handler_tx.try_send((data.into(), dest_addr)) {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Channel closed"));
                    }
                }
                (Some(Node { id, .. }), _) => {
                    if let Err(TrySendError::Closed(_)) = tcp_handler_tx.try_send((data.into(), *id)) {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Channel closed"));
                    }
                }
                _ => continue
            };
        }
    })
}

async fn heartbeat_schedule(
    server_addr: SocketAddr,
    mut msg_socket: UdpMsgSocket<'_>,
    seq: &AtomicU32,
) -> Result<(), Box<dyn Error>> {
    loop {
        let msg = UdpMsg::Heartbeat(0, 0, HeartbeatType::Req);
        msg_socket.write(&msg, server_addr).await?;
        let temp_seq = seq.load(Ordering::SeqCst);
        let local_wan_addr = LOCAL_NODE.read().wan_udp_addr;
        let mapping = MAPPING.get_all();

        for (_, node) in mapping {
            if let Node {
                id: node_id,
                wan_udp_addr: Some(peer_wan_addr),
                lan_udp_addr: Some(peer_lan_addr),
                ..
            } = node {
                let dest_addr = match local_wan_addr {
                    Some(local_wan_addr) if local_wan_addr.ip() == peer_wan_addr.ip() => {
                        peer_lan_addr
                    }
                    _ => peer_wan_addr
                };

                let heartbeat_packet = UdpMsg::Heartbeat(node_id, temp_seq, HeartbeatType::Req);
                msg_socket.write(&heartbeat_packet, dest_addr).await?;
            }
        }

        time::sleep(Duration::from_secs(5)).await;
        seq.fetch_add(1, Ordering::SeqCst);
    }
}

async fn udp_receiver(
    mut msg_socket: UdpMsgSocket<'_>,
    to_tun: UnboundedSender<Box<[u8]>>,
    heartbeat_seq: &AtomicU32,
) -> Result<(), Box<dyn Error>> {
    let local_node_id = LOCAL_NODE.read().id;

    loop {
        if let Ok((msg, peer_addr)) = msg_socket.read().await {
            match msg {
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req) => {
                    if local_node_id != node_id {
                        continue;
                    }

                    let resp = Heartbeat(node_id, seq, HeartbeatType::Resp);
                    msg_socket.write(&resp, peer_addr).await?;
                }
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp)
                if seq == heartbeat_seq.load(Ordering::SeqCst) &&
                    node_id != 0 => {
                    DIRECT_NODE_LIST.update(node_id);
                }
                UdpMsg::Data(data) => to_tun.send(data.into())?,
                _ => continue
            }
        }
    }
}

async fn udp_sender(
    mut msg_socket: UdpMsgSocket<'_>,
    mut from_tun: Receiver<(Box<[u8]>, SocketAddr)>,
) -> Result<(), Box<dyn Error>> {
    while let Some((data, dest_addr)) = from_tun.recv().await {
        let data = UdpMsg::Data(&data);
        msg_socket.write(&data, dest_addr).await?;
    }
    Ok(())
}

async fn udp_handler(
    udp_socket: UdpSocket,
    channel_rx: Receiver<(Box<[u8]>, SocketAddr)>,
    channel_tx: UnboundedSender<Box<[u8]>>,
    server_addr: SocketAddr,
    rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let msg_socket = UdpMsgSocket::new(&udp_socket, rc4);
    let seq = AtomicU32::new(0);

    tokio::select! {
        res = heartbeat_schedule(server_addr, msg_socket.clone(), &seq) => res,
        res = udp_receiver(msg_socket.clone(), channel_tx, &seq) => res,
        res = udp_sender(msg_socket, channel_rx) => res
    }
}

async fn tcp_receiver<Rx: AsyncRead + Unpin>(
    msg_reader: &mut TcpMsgReader<'_, Rx>,
    to_tun: &UnboundedSender<Box<[u8]>>,
) -> Result<(), Box<dyn Error>> {
    let local_node_id = LOCAL_NODE.read().id;

    loop {
        let msg = msg_reader.read().await?;

        match msg {
            TcpMsg::NodeMap(node_map) => {
                if let Some(node) = node_map.get(&local_node_id) {
                    LOCAL_NODE.write().wan_udp_addr = node.wan_udp_addr
                }

                let mapping: HashMap<Ipv4Addr, Node> = node_map.into_iter()
                    .map(|(_, node)| (node.tun_addr, node))
                    .collect();

                MAPPING.update_all(mapping);
            }
            TcpMsg::Forward(packet, _) => to_tun.send(packet.into())?,
            _ => continue
        }
    }
}

async fn tcp_sender<Tx: AsyncWrite + Unpin>(
    msg_writer: &mut TcpMsgWriter<'_, Tx>,
    from_tun: &mut Receiver<(Box<[u8]>, NodeId)>,
) -> Result<(), Box<dyn Error>> {
    while let Some((data, dest_node_id)) = from_tun.recv().await {
        let msg = TcpMsg::Forward(&data, dest_node_id);
        msg_writer.write(&msg).await?;
    }
    Ok(())
}

async fn tcp_handler(
    mut channel_rx: Receiver<(Box<[u8]>, NodeId)>,
    channel_tx: UnboundedSender<Box<[u8]>>,
    server_addr: SocketAddr,
    rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    loop {
        let inner_channel_tx = &channel_tx;
        let inner_channel_rx = &mut channel_rx;
        let mut tx_rc4 = rc4;
        let mut rx_rc4 = rc4;

        let process = async move {
            let mut stream = TcpStream::connect(server_addr).await?;
            let (mut rx, mut tx) = stream.split();
            let mut msg_reader = TcpMsgReader::new(&mut rx, &mut rx_rc4);
            let mut msg_writer = TcpMsgWriter::new(&mut tx, &mut tx_rc4);

            let msg = {
                let mut node_guard = LOCAL_NODE.write();
                node_guard.register_time = Utc::now().timestamp();
                TcpMsg::Register((*node_guard).clone())
            };

            msg_writer.write(&msg).await?;
            let msg = msg_reader.read().await?;

            let res = match msg {
                TcpMsg::Result(MsgResult::Success) => Ok(()),
                TcpMsg::Result(MsgResult::Timeout) => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Node register timeout"))),
                _ => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Node register error")))
            };

            res?;

            tokio::select! {
                res = tcp_receiver(&mut msg_reader, inner_channel_tx) => res,
                res = tcp_sender(&mut msg_writer, inner_channel_rx) => res
            }
        };

        if let Err(e) = process.await {
            error!("{}", e)
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeInfo {
    pub id: NodeId,
    pub tun_addr: Ipv4Addr,
    pub lan_udp_addr: Option<SocketAddr>,
    pub source_udp_addr: Option<SocketAddr>,
    pub register_time: String,
    pub direct: bool,
}

fn node_to_node_info(
    (_, node): (Ipv4Addr, Node),
    local_node_id: NodeId,
) -> NodeInfo {
    let utc: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp(node.register_time, 0), Utc);
    let local_time: DateTime<Local> = DateTime::from(utc);

    let direct = if node.id == local_node_id {
        true
    } else {
        DIRECT_NODE_LIST.contain(&node.id)
    };

    NodeInfo {
        id: node.id,
        tun_addr: node.tun_addr,
        lan_udp_addr: node.lan_udp_addr,
        source_udp_addr: node.wan_udp_addr,
        register_time: local_time.format("%Y-%m-%d %H:%M:%S").to_string(),
        direct,
    }
}

fn stdin(local_node_id: NodeId) -> io::Result<()> {
    let stdin = std::io::stdin();

    loop {
        let mut cmd = String::new();
        let len = stdin.read_line(&mut cmd)?;

        if len == 0 {
            return Ok(());
        }

        match cmd.trim() {
            "show" => {
                let map = MAPPING.get_all();

                let node_list: Vec<NodeInfo> = map.into_iter()
                    .map(|node| node_to_node_info(node, local_node_id))
                    .collect();

                let json = node_list.to_json_string_pretty()?;
                println!("{}", json)
            }
            _ => ()
        }
    }
}