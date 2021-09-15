use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use chrono::Utc;
use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time;

use crate::common::proto::{HeartbeatType, MTU, Node, NodeId, TcpMsg, UdpMsg};
use crate::common::proto;
use crate::common::proto::UdpMsg::Heartbeat;
use crate::tun::{create_device, Rx, Tx};

static MAPPING: Lazy<LocalMapping> = Lazy::new(|| LocalMapping::new());
static DIRECT_NODE_LIST: Lazy<DirectNodeList> = Lazy::new(|| DirectNodeList::new());

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

fn direct_node_list_schedule() {
    tokio::spawn(async move {
        loop {
            {
                let guard = DIRECT_NODE_LIST.list.read();

                let node_id_list: Vec<NodeId> = guard.iter()
                    .filter(|(node_id, update_time)| update_time.elapsed() > Duration::from_secs(30))
                    .map(|(node_id, _)| *node_id)
                    .collect();

                drop(guard);

                let mut writer_guard = DIRECT_NODE_LIST.list.write();

                for node_id in node_id_list {
                    writer_guard.remove(&node_id);
                }

                drop(writer_guard);
            }

            time::sleep(Duration::from_secs(30)).await;
        }
    });
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

struct TunAdapter {
    ip_addr: Ipv4Addr,
    netmask: Ipv4Addr,
}

async fn start(
    server_addr: SocketAddr,
    rc4: Rc4,
    TunAdapter { ip_addr: tun_addr, netmask }: TunAdapter,
) -> Result<(), Box<dyn Error>> {
    let node_id: NodeId = rand::random();
    let device = create_device(tun_addr, netmask)?;

    info!("Tun adapter ip address: {}", tun_addr);
    Ok(())
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
    local_tun_addr: Ipv4Addr,
    tcp_handler_tx: Sender<Box<[u8]>>,
    udp_handler_tx: Sender<(Box<[u8]>, SocketAddr)>,
    mut tun_rx: Box<dyn Rx>,
) -> JoinHandle<io::Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut buff = [0u8; MTU];
        let mut out = [0u8; 2048];

        loop {
            let data = match tun_rx.recv_packet(&mut buff)? {
                0 => continue,
                len => &buff[..len]
            };

            let ipv4 = Ipv4Packet::new_unchecked(data);
            let Ipv4Address(octets) = ipv4.dst_addr();
            let peer_tun_addr = Ipv4Addr::from(octets);

            let guard = MAPPING.map.read();

            let res = match guard.get(&peer_tun_addr) {
                Some(
                    Node {
                        id: node_id,
                        source_udp_addr: Some(peer_addr),
                        lan_udp_addr: Some(peer_lan_addr),
                        ..
                    }
                ) if DIRECT_NODE_LIST.contain(node_id) => {
                    let dest_addr = match guard.get(&local_tun_addr) {
                        Some(Node { source_udp_addr: Some(local_addr), .. }) if local_addr.ip() == peer_addr.ip() => {
                            *peer_lan_addr
                        }
                        _ => *peer_addr
                    };

                    let packet = UdpMsg::Data(data).encode(&mut out)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

                    udp_handler_tx.try_send((packet.into(), dest_addr)).map_err(|e| {
                        match e {
                            TrySendError::Full((data, _)) => TrySendError::Full(data),
                            TrySendError::Closed((data, _)) => TrySendError::Closed(data)
                        }
                    })
                }
                Some(Node { id, .. }) => {
                    let packet = TcpMsg::Forward(data, *id).encode(&mut out)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    tcp_handler_tx.try_send(packet.into())
                }
                _ => continue
            };

            if let Err(TrySendError::Closed(_)) = res {
                return Ok(());
            }
        }
    })
}

async fn heartbeat_schedule(
    server_addr: SocketAddr,
    udp_socket: &UdpSocket,
    rc4: Rc4,
    seq: &AtomicU32,
) -> Result<(), Box<dyn Error>> {
    let mut buff = [0u8; 2048];
    let mut out = [0u8; 2048];

    let data = Heartbeat(0, 0, HeartbeatType::Resp).encode(&mut buff)?;
    let mut temp_rc4 = rc4;
    let server_heartbeat_packet: Box<[u8]> = proto::crypto(data, &mut out, &mut temp_rc4)?.into();

    loop {
        udp_socket.send_to(&server_heartbeat_packet, server_addr).await?;

        let temp_seq = seq.load(Ordering::SeqCst);

        for (_, node) in MAPPING.get_all() {
            if let Node { id: node_id, source_udp_addr: Some(dest_addr), .. } = node {
                let mut inner_rc4 = rc4;

                let heartbeat_packet = Heartbeat(node_id, temp_seq, HeartbeatType::Req).encode(&mut buff)?;
                let packet = proto::crypto(heartbeat_packet, &mut out, &mut inner_rc4)?;
                udp_socket.send_to(packet, dest_addr).await?;
            }
            time::sleep(Duration::from_secs(5)).await
        }
        seq.fetch_add(1, Ordering::SeqCst);
    }
}

async fn udp_receiver(
    udp_socket: &UdpSocket,
    to_tun: UnboundedSender<Box<[u8]>>,
    rc4: Rc4,
    heartbeat_seq: &AtomicU32,
) -> Result<(), Box<dyn Error>> {
    let mut buff = [0u8; 2048];
    let mut out = [0u8; 2048];

    loop {
        let mut inner_rc4 = rc4;
        let (len, peer_addr) = udp_socket.recv_from(&mut buff).await?;
        let data = &buff[..len];

        let packet = proto::crypto(data, &mut out, &mut inner_rc4)?;

        match UdpMsg::decode(packet)? {
            Heartbeat(node_id, seq, HeartbeatType::Req) => {
                let resp = Heartbeat(node_id, seq, HeartbeatType::Resp).encode(&mut buff)?;
                let packet = proto::crypto(resp, &mut out, &mut inner_rc4)?;
                udp_socket.send_to(packet, peer_addr).await?;
            }
            Heartbeat(node_id, seq, HeartbeatType::Resp) if seq == heartbeat_seq.load(Ordering::SeqCst) => {
                DIRECT_NODE_LIST.update(node_id);
            }
            UdpMsg::Data(data) => to_tun.send(data.into())?,
            _ => continue
        }
    }
}

async fn udp_sender(
    udp_socket: &UdpSocket,
    mut from_tun: Receiver<(Box<[u8]>, SocketAddr)>,
    rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let mut buff = vec![0u8; 65535];

    while let Some((data, dest_addr)) = from_tun.recv().await {
        let mut inner_rc4 = rc4;
        let out = proto::crypto(&data, &mut buff, &mut inner_rc4)?;
        udp_socket.send_to(out, dest_addr).await?;
    }
    Ok(())
}

async fn udp_handler(
    channel_rx: Receiver<(Box<[u8]>, SocketAddr)>,
    channel_tx: UnboundedSender<Box<[u8]>>,
    udp_socket_addr: SocketAddr,
    server_addr: SocketAddr,
    rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let udp_socket = UdpSocket::bind(udp_socket_addr).await?;
    let seq = AtomicU32::new(0);

    tokio::select! {
        res = heartbeat_schedule(server_addr, &udp_socket, rc4, &seq) => res,
        res = udp_receiver(&udp_socket, channel_tx, rc4, &seq) => res,
        res = udp_sender(&udp_socket, channel_rx, rc4) => res
    }
}

async fn tcp_handler() -> Result<(), Box<dyn Error>> {
    Ok(())
}