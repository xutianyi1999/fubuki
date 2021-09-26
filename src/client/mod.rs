use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::MAIN_SEPARATOR;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::signal;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time;

use crate::common::net::get_interface_addr;
use crate::common::persistence::ToJson;
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
    is_direct: bool,
) -> Result<(), Box<dyn Error>> {
    let node_id: NodeId = rand::random();
    let device = create_device(tun_addr, netmask)?;
    let (tun_tx, tun_rx) = device.split();

    let (to_tun, from_handler) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (to_tcp_handler, from_tun2) = mpsc::channel::<(Box<[u8]>, NodeId)>(10);


    if is_direct {
        let lan_ip = get_interface_addr(server_addr).await?;
        let udp_socket = UdpSocket::bind((lan_ip, 0)).await?;
        let (to_udp_handler, from_tun1) = mpsc::channel::<(Box<[u8]>, SocketAddr)>(10);

        let node = Node {
            id: node_id,
            tun_addr,
            lan_udp_addr: Some(udp_socket.local_addr()?),
            source_udp_addr: None,
            register_time: String::new(),
        };

        // async move {}
    } else {
        let node = Node {
            id: node_id,
            tun_addr,
            lan_udp_addr: None,
            source_udp_addr: None,
            register_time: String::new(),
        };
    }

    info!("Tun adapter ip address: {}", tun_addr);

    let r = tokio::select! {
        res = direct_node_list_schedule() => res?,
        res = mpsc_to_tun(from_handler, tun_tx) => res??,
        // res = tun_to_mpsc(tun_addr, to_tcp_handler, to_udp_handler, tun_rx) => res??,
        // res = udp_handler(from_tun1, to_tun.clone(),  server_addr, rc4) => res?,
        // res = tcp_handler(from_tun2, to_tun, server_addr, rc4) => res?,
        res = signal::ctrl_c() => res?
    };
    Ok(())
}

fn direct_node_list_schedule() -> JoinHandle<()> {
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
    local_tun_addr: Ipv4Addr,
    tcp_handler_tx: Sender<(Box<[u8]>, NodeId)>,
    udp_handler_tx: Sender<(Box<[u8]>, SocketAddr)>,
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

                    udp_handler_tx.try_send((data.into(), dest_addr)).map_err(|e| {
                        match e {
                            TrySendError::Full(_) => TrySendError::Full(()),
                            TrySendError::Closed(_) => TrySendError::Closed(())
                        }
                    })
                }
                Some(Node { id, .. }) => {
                    tcp_handler_tx.try_send((data.into(), *id)).map_err(|e| {
                        match e {
                            TrySendError::Full(_) => TrySendError::Full(()),
                            TrySendError::Closed(_) => TrySendError::Closed(())
                        }
                    })
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
    let mut out = vec![0u8; 65535];

    while let Some((data, dest_addr)) = from_tun.recv().await {
        let mut inner_rc4 = rc4;

        let data = UdpMsg::Data(&data).encode(&mut buff)?;
        let out = proto::crypto(data, &mut out, &mut inner_rc4)?;

        udp_socket.send_to(out, dest_addr).await?;
    }
    Ok(())
}

async fn udp_handler(
    channel_rx: Receiver<(Box<[u8]>, SocketAddr)>,
    channel_tx: UnboundedSender<Box<[u8]>>,
    server_addr: SocketAddr,
    rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let udp_socket = UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0)).await?;
    let seq = AtomicU32::new(0);

    tokio::select! {
        res = heartbeat_schedule(server_addr, &udp_socket, rc4, &seq) => res,
        res = udp_receiver(&udp_socket, channel_tx, rc4, &seq) => res,
        res = udp_sender(&udp_socket, channel_rx, rc4) => res
    }
}

async fn tcp_receiver<Rx: AsyncRead + Unpin>(
    mut tcp_rx: Rx,
    to_tun: &UnboundedSender<Box<[u8]>>,
    mut rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let mut buff = vec![0u8; 65535];
    let mut out = vec![0u8; 65535];

    loop {
        let len = tcp_rx.read_u16().await?;
        let data = &mut buff[..len as usize];
        tcp_rx.read_exact(data).await?;

        let data = proto::crypto(data, &mut out, &mut rc4)?;

        match TcpMsg::decode(data)? {
            TcpMsg::NodeList(node_list) => {
                let mapping: HashMap<Ipv4Addr, Node> = node_list.into_iter()
                    .map(|node| (node.tun_addr, node))
                    .collect();

                MAPPING.update_all(mapping);
            }
            TcpMsg::Forward(packet, _) => to_tun.send(packet.into())?,
            _ => continue
        }
    }
}

async fn tcp_sender<Tx: AsyncWrite + Unpin>(
    mut tcp_tx: Tx,
    from_tun: &mut Receiver<(Box<[u8]>, NodeId)>,
    mut rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let mut buff = vec![0u8; 65535];
    let mut out = vec![0u8; 65535];

    while let Some((data, dest_node_id)) = from_tun.recv().await {
        let data = TcpMsg::Forward(&data, dest_node_id).encode(&mut buff)?;
        let packet = proto::crypto(data, &mut out, &mut rc4)?;

        let len = packet.len();
        buff[..2].copy_from_slice(&len.to_be_bytes());
        buff[2..len + 2].copy_from_slice(packet);

        tcp_tx.write_all(&buff[..len + 2]).await?;
    }
    Ok(())
}

async fn tcp_handler(
    mut node: Node,
    mut channel_rx: Receiver<(Box<[u8]>, NodeId)>,
    channel_tx: UnboundedSender<Box<[u8]>>,
    server_addr: SocketAddr,
    rc4: Rc4,
) -> Result<(), Box<dyn Error>> {
    let mut tx_rc4 = rc4;
    let mut rx_rc4 = rc4;

    let mut buff = vec![0u8; 65535];
    let mut out = vec![0u8; 65535];

    loop {
        let inner_channel_tx = &channel_tx;
        let inner_channel_rx = &mut channel_rx;
        let inner_node = &mut node;
        let inner_buff = &mut buff;
        let inner_out = &mut out;

        let process = async move {
            let mut stream = TcpStream::connect(server_addr).await?;
            inner_node.register_time = Utc::now().to_string();

            let data = TcpMsg::Register(inner_node.clone()).encode(inner_buff)?;
            let packet = proto::crypto(data, inner_out, &mut tx_rc4)?;
            let len = packet.len();

            inner_buff[..2].copy_from_slice(&len.to_be_bytes());
            inner_buff[2..len + 2].copy_from_slice(packet);

            stream.write_all(&inner_buff[..len + 2]).await?;

            let len = stream.read_u16().await?;
            let mut buff = vec![0u8; len as usize];
            stream.read_exact(&mut buff).await?;
            // proto::crypto()
            let (rx, tx) = stream.split();

            tokio::select! {
                res = tcp_receiver(rx, inner_channel_tx, rx_rc4) => res,
                res = tcp_sender(tx,inner_channel_rx, tx_rc4) => res
            }
        };

        if let Err(e) = process.await {
            error!("{}", e)
        }
    }
}

fn stdin() -> io::Result<()> {
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
                let node_list: Vec<Node> = map.into_iter()
                    .map(|(_, v)| v)
                    .collect();

                let json = node_list.to_json_string_pretty()?;
                println!("{}", json)
            }
            _ => ()
        }
    }
}