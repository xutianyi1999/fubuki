use std::borrow::Borrow;
use std::cell::{Cell, UnsafeCell};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use crossbeam_channel::crossbeam_channel_internal;
use crossbeam_utils::atomic::AtomicCell;
use crypto::rc4::Rc4;
use parking_lot::{RawRwLock, RwLock};
use parking_lot::lock_api::{RwLockReadGuard, RwLockWriteGuard};
use serde::Serialize;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use tokio::{sync, time};
use tokio::io::BufReader;
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;

use crate::{ClientConfig, TunConfig};
use crate::common::net::get_interface_addr;
use crate::common::net::msg_operator::{TCP_BUFF_SIZE, TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, MTU, Node, NodeId, Seq, TcpMsg, UdpMsg};
use crate::common::net::proto::UdpMsg::Heartbeat;
use crate::common::persistence::ToJson;
use crate::common::PointerWrap;
use crate::tun::create_device;
use crate::tun::TunDevice;

const CHANNEL_SIZE: usize = 100;

static mut MAPPING: PointerWrap<NodeMapping> = PointerWrap::default();
static mut DIRECT_NODE_LIST: PointerWrap<DirectNodeList> = PointerWrap::default();
static mut LOCAL_NODE: PointerWrap<RwLock<Node>> = PointerWrap::default();

fn get_mapping() -> &'static PointerWrap<NodeMapping> {
    unsafe { &MAPPING }
}

fn get_direct_node_list() -> &'static PointerWrap<DirectNodeList> {
    unsafe { &DIRECT_NODE_LIST }
}

fn get_local_node() -> &'static PointerWrap<RwLock<Node>> {
    unsafe { &LOCAL_NODE }
}

struct WanAddrMapping {
    // tun_addr -> wan_addr
    map: HashMap<Ipv4Addr, AtomicCell<Option<IpAddr>>>,
    version: AtomicU8,
}

impl WanAddrMapping {
    fn new(tun_addresses: &[Ipv4Addr]) -> Self {
        let map: HashMap<Ipv4Addr, AtomicCell<Option<IpAddr>>> = tun_addresses.iter()
            .map(|addr| (*addr, AtomicCell::new(None)))
            .collect();

        WanAddrMapping {
            map,
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn update(&self, tun_addr: &Ipv4Addr, wan_addr: IpAddr) {
        let v = match self.map.get(tun_addr) {
            None => return,
            Some(v) => v
        };

        if v.load() != Some(wan_addr) {
            v.store(Some(wan_addr));
            self.version.fetch_add(1, Ordering::Relaxed)
        }
    }

    fn load(&self) -> HashMap<Ipv4Addr, Option<IpAddr>> {
        self.map.iter()
            .map(|(k, v)| (*k, v.load()))
            .collect()
    }
}

struct DirectNodeList {
    list: RwLock<HashMap<NodeId, AtomicI64>>,
    version: AtomicU8,
}

impl DirectNodeList {
    fn new() -> Self {
        DirectNodeList {
            list: RwLock::new(HashMap::new()),
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn try_load(&self) -> Option<HashSet<NodeId>> {
        // TODO 可以尝试在此添加缓存
        let guard = self.list.try_read()?;

        let set: HashSet<NodeId> = guard.keys()
            .map(|v| *v)
            .collect();

        Some(set)
    }

    fn update(&self, node_id: NodeId) {
        let now = Utc::now().timestamp();

        {
            let guard = match self.list.try_read() {
                Some(guard) => guard,
                None => return
            };

            if let Some(time) = guard.get(&node_id) {
                time.store(now, Ordering::Relaxed);
                return;
            }
        }

        let option = {
            let mut guard = match self.list.try_write() {
                Some(guard) => guard,
                None => return
            };

            guard.insert(node_id, AtomicI64::new(now))
        };

        if option.is_none() {
            self.version.fetch_add(1, Ordering::Relaxed)
        }
    }

    fn try_update_all(&self, map: HashMap<NodeId, AtomicI64>) {
        match self.list.try_write() {
            Some(mut guard) => *guard = map,
            None => return
        };

        self.version.fetch_add(1, Ordering::Relaxed);
    }
}

async fn direct_node_list_schedule() {
    loop {
        time::sleep(Duration::from_secs(30)).await;
        let now = Utc::now().timestamp();

        let new_map = {
            let guard = match get_direct_node_list().list.try_read() {
                Some(guard) => guard,
                None => continue
            };

            let mut new = HashMap::new();

            for (k, v) in guard.iter() {
                let time = v.load(Ordering::Relaxed);

                if now - time <= 30 {
                    new.insert(*k, AtomicI64::new(time))
                }
            }
            new
        };

        get_direct_node_list().try_update_all(new_map)
    }
}

struct NodeMapping {
    // local_addr -> (tun_addr -> node)
    map: HashMap<Ipv4Addr, RwLock<Arc<HashMap<Ipv4Addr, Node>>>>,
    version: AtomicU8,
}

impl NodeMapping {
    fn new(tun_addresses: &[Ipv4Addr]) -> Self {
        let map: HashMap<Ipv4Addr, RwLock<Arc<HashMap<Ipv4Addr, Node>>>> = tun_addresses.iter()
            .map(|v| (*v, RwLock::new(Arc::new(HashMap::new()))))
            .collect();

        NodeMapping {
            map,
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn update(&self, local_addr: &Ipv4Addr, map: HashMap<Ipv4Addr, Node>) {
        let map = Arc::new(map);

        if let Some(lock) = self.map.get(local_addr) {
            *lock.write() = map;
            self.version.fetch_add(1, Ordering::Relaxed)
        }
    }

    fn try_load(&self) -> Option<HashMap<Ipv4Addr, Arc<HashMap<Ipv4Addr, Node>>>> {
        let mut map = HashMap::new();

        for (k, v) in self.map {
            map.insert(k, v.try_read()?.clone())
        };
        Some(map)
    }
}

fn init(node: Node) {
    unsafe {
        let p = Box::new(NodeMapping::new());
        MAPPING = PointerWrap::new(Box::leak(p));

        let p = Box::new(DirectNodeList::new());
        DIRECT_NODE_LIST = PointerWrap::new(Box::leak(p));

        let p = Box::new(RwLock::new(node));
        LOCAL_NODE = PointerWrap::new(Box::leak(p));
    }
}

pub(super) async fn start(configs: Vec<ClientConfig>) -> Result<()> {
    let tun_config: Vec<TunConfig> = configs.iter()
        .map(|v| v.tun.clone())
        .collect();

    let server_addr = lookup_host(server_addr).await?.next().ok_or_else(|| anyhow!("Server host not found"))?;
    let rc4 = Rc4::new(key.as_bytes());
    let tun_device = create_device(tun_config).context("Failed create tun adapter")?;

    let (to_tun, from_handler) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (to_tcp_handler, from_tun2) = mpsc::channel::<(Box<[u8]>, NodeId)>(CHANNEL_SIZE);

    let node = Node {
        id: rand::random(),
        tun_addr,
        lan_udp_addr: None,
        wan_udp_addr: None,
        register_time: 0,
    };

    init(node);

    info!("Tun adapter ip address: {}", tun_addr);
    info!("Client start");

    tokio::task::spawn_blocking(move || if let Err(e) = stdin() { error!("Stdin error -> {}", e) });

    if direct {
        // server_addr do not use loop address
        let lan_ip = get_interface_addr(server_addr).await
            .context("Failed to get lan address")?;

        let udp_socket = UdpSocket::bind((lan_ip, 0)).await
            .context("Failed to create UDP socket")?;

        let (to_udp_handler, from_tun1) = mpsc::unbounded_channel::<(Box<[u8]>, SocketAddr)>();

        get_local_node().write().lan_udp_addr = Some(udp_socket.local_addr()?);

        tokio::select! {
            _ = direct_node_list_schedule() => (),
            res = mpsc_to_tun(from_handler, tun_tx) => res?.context("MPSC to TUN handler error")?,
            res = tun_to_mpsc(to_tcp_handler, Some(to_udp_handler), tun_rx) => res?.context("TUN to MPSC handler error")?,
            res = udp_handler(udp_socket, from_tun1, to_tun.clone(), server_addr, rc4) => res.context("UDP handler error")?,
            _ = tcp_handler(from_tun2, to_tun, server_addr, rc4) => (),
        }
    } else {
        tokio::select! {
            res = mpsc_to_tun(from_handler, tun_tx) => res?.context("MPSC to TUN handler error")?,
            res = tun_to_mpsc(to_tcp_handler, None, tun_rx) => res?.context("TUN to MPSC handler error")?,
            _ = tcp_handler(from_tun2, to_tun, server_addr, rc4) => (),
        }
    };

    warn!("Client down");
    Ok(())
}

fn mpsc_to_tun(
    mut mpsc_rx: UnboundedReceiver<Box<[u8]>>,
    mut tun_tx: Box<dyn Tx>,
) -> JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || {
        while let Some(packet) = mpsc_rx.blocking_recv() {
            tun_tx.send_packet(&packet).context("Write packet to tun error")?;
        };
        Ok(())
    })
}

fn tun_to_mpsc(
    tcp_handler_tx: Sender<(Box<[u8]>, NodeId)>,
    udp_handler_tx_opt: Option<UnboundedSender<(Box<[u8]>, SocketAddr)>>,
    mut tun_rx: Box<dyn Rx>,
) -> JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut buff = [0u8; MTU];

        loop {
            let data = match tun_rx.recv_packet(&mut buff).context("Read packet from tun error")? {
                0 => continue,
                len => &buff[..len]
            };

            let ipv4 = Ipv4Packet::new_unchecked(data);
            let Ipv4Address(octets) = ipv4.dst_addr();
            let peer_tun_addr = Ipv4Addr::from(octets);

            let guard = get_mapping().map.read();
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
                ) if get_direct_node_list().contain(node_id) => {
                    let dest_addr = match get_local_node().read().wan_udp_addr {
                        Some(local_wan_addr) if local_wan_addr.ip() == peer_wan_addr.ip() => {
                            *peer_lan_addr
                        }
                        _ => *peer_wan_addr
                    };

                    udp_handler_tx.send((data.into(), dest_addr))?;
                }
                (Some(Node { id, .. }), _) => {
                    if let Err(TrySendError::Closed(_)) = tcp_handler_tx.try_send((data.into(), *id)) {
                        return Err(anyhow!("TCP handler channel closed"));
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
    seq: &Cell<Seq>,
) -> Result<()> {
    let local_node_id = get_local_node().read().id;

    loop {
        let msg = UdpMsg::Heartbeat(local_node_id, 0, HeartbeatType::Req);
        msg_socket.write(&msg, server_addr).await?;

        let temp_seq = seq.get();
        let local_wan_addr = get_local_node().try_read().wan_udp_addr;
        let mapping = get_mapping().get();

        for (_, node) in mapping {
            if node.id == local_node_id {
                continue;
            }

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

        if seq.get() == Seq::MAX {
            seq.set(0);
        } else {
            seq.set(seq.get() + 1);
        }
    }
}

async fn udp_receiver(
    mut msg_socket: UdpMsgSocket<'_>,
    to_tun: UnboundedSender<Box<[u8]>>,
    heartbeat_seq: &Cell<Seq>,
) -> Result<()> {
    let local_node_id = get_local_node().read().id;

    loop {
        if let Ok((msg, peer_addr)) = msg_socket.read().await {
            match msg {
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req) if local_node_id == node_id => {
                    let resp = Heartbeat(node_id, seq, HeartbeatType::Resp);
                    match msg_socket.try_write(&resp, peer_addr) {
                        Ok(_) => (),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp)
                if node_id != 0 && seq == heartbeat_seq.get()
                => {
                    get_direct_node_list().update(node_id);
                }
                UdpMsg::Data(data) => to_tun.send(data.into())?,
                _ => continue
            }
        }
    }
}

async fn udp_sender(
    mut msg_socket: UdpMsgSocket<'_>,
    mut from_tun: UnboundedReceiver<(Box<[u8]>, SocketAddr)>,
) -> Result<()> {
    while let Some((data, dest_addr)) = from_tun.recv().await {
        let data = UdpMsg::Data(&data);
        msg_socket.write(&data, dest_addr).await?;
    }
    Ok(())
}

async fn udp_handler(
    udp_socket: UdpSocket,
    channel_rx: UnboundedReceiver<(Box<[u8]>, SocketAddr)>,
    channel_tx: UnboundedSender<Box<[u8]>>,
    server_addr: SocketAddr,
    rc4: Rc4,
) -> Result<()> {
    let msg_socket = UdpMsgSocket::new(&udp_socket, rc4);
    let seq = Cell::new(0);

    tokio::select! {
        res = heartbeat_schedule(server_addr, msg_socket.clone(), &seq) => res.context("Heartbeat schedule error"),
        res = udp_receiver(msg_socket.clone(), channel_tx, &seq) => res.context("UDP receiver error"),
        res = udp_sender(msg_socket, channel_rx) => res.context("UDP sender error")
    }
}

async fn tcp_handler(
    mut from_tun: Receiver<(Box<[u8]>, NodeId)>,
    to_tun: crossbeam_channel::Sender<Box<[u8]>>,
    server_addr: &str,
    tun_add: Ipv4Addr,
    rc4: Rc4,
) {
    let inner_to_tun = &to_tun;
    let inner_from_tun = &mut from_tun;

    loop {
        let mut tx_rc4 = rc4;
        let mut rx_rc4 = rc4;

        let process = async move {
            let mut stream = TcpStream::connect(server_addr).await.context("Connect to server error")?;
            info!("Server connected");

            let (rx, mut tx) = stream.split();
            let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

            let mut msg_reader = TcpMsgReader::new(&mut rx, &mut rx_rc4);
            let mut msg_writer = TcpMsgWriter::new(&mut tx, &mut tx_rc4);

            let msg = {
                let mut node_guard = get_local_node().write();
                node_guard.register_time = Utc::now().timestamp();
                TcpMsg::Register((*node_guard).clone())
            };

            msg_writer.write(&msg).await?;
            let msg = msg_reader.read().await?;

            match msg {
                TcpMsg::Result(MsgResult::Success) => (),
                TcpMsg::Result(MsgResult::Timeout) => return Err(anyhow!("Register timeout")),
                _ => return Err(anyhow!("Register error"))
            };

            let (tx, mut rx) = sync::mpsc::unbounded_channel::<TcpMsg>();

            let latest_recv_heartbeat_time = Cell::new(Instant::now());
            let latest_recv_heartbeat_time_ref1 = &latest_recv_heartbeat_time;
            let latest_recv_heartbeat_time_ref2 = &latest_recv_heartbeat_time;

            let seq: Cell<Seq> = Cell::new(0);
            let inner_seq1 = &seq;
            let inner_seq2 = &seq;

            let fut1 = async move {
                let local_node_id = get_local_node().read().id;

                loop {
                    match msg_reader.read().await? {
                        TcpMsg::NodeMap(node_map) => {
                            if let Some(node) = node_map.get(&local_node_id) {
                                get_local_node().write().wan_udp_addr = node.wan_udp_addr
                            }

                            let mapping: HashMap<Ipv4Addr, Node> = node_map.into_iter()
                                .map(|(_, node)| (node.tun_addr, node))
                                .collect();

                            get_mapping().update(mapping);
                        }
                        TcpMsg::Forward(packet, _) => inner_to_tun.send(packet.into())?,
                        TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                            let heartbeat = TcpMsg::Heartbeat(seq, HeartbeatType::Resp);
                            tx.send(heartbeat).map_err(|e| anyhow!(e.to_string()))?;
                        }
                        TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                            if inner_seq1.get() == recv_seq {
                                latest_recv_heartbeat_time_ref1.set(Instant::now());
                            }
                        }
                        _ => continue
                    }
                }
            };

            let fut2 = async move {
                let mut heartbeat_interval = time::interval(Duration::from_secs(5));
                let mut check_heartbeat_timeout = time::interval(Duration::from_secs(30));

                loop {
                    tokio::select! {
                        opt = rx.recv() => {
                             match opt {
                                Some(heartbeat) => msg_writer.write(&heartbeat).await?,
                                None => return Ok(())
                            }
                        }
                        opt = inner_from_tun.recv() => {
                            match opt {
                                Some((data, dest_node_id)) => {
                                    let msg = TcpMsg::Forward(&data, dest_node_id);
                                    msg_writer.write(&msg).await?;
                                }
                                None => return Ok(())
                            }
                        }
                        _ = heartbeat_interval.tick() => {
                            if inner_seq2.get() == Seq::MAX {
                                inner_seq2.set(0);
                            } else {
                                inner_seq2.set(inner_seq2.get() + 1);
                            }

                            let heartbeat = TcpMsg::Heartbeat(inner_seq2.get(), HeartbeatType::Req);
                            msg_writer.write(&heartbeat).await?;
                        }
                        _ = check_heartbeat_timeout.tick() => {
                            if latest_recv_heartbeat_time_ref2.get().elapsed() > Duration::from_secs(30) {
                                return Err(anyhow!("Heartbeat recv timeout"))
                            }
                        }
                    }
                }
            };

            tokio::select! {
                res = fut1 => res,
                res = fut2 => res
            }
        };

        if let Err(e) = process.await {
            error!("TCP handler error -> {:?}", e)
        }

        time::sleep(Duration::from_secs(3)).await;
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
        get_direct_node_list().contain(&node.id)
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

fn stdin() -> io::Result<()> {
    let stdin = std::io::stdin();
    let local_node_id = get_local_node().read().id;

    loop {
        let mut cmd = String::new();
        let len = stdin.read_line(&mut cmd)?;

        if len == 0 {
            return Ok(());
        }

        match cmd.trim() {
            "show" => {
                let map = get_mapping().get();

                let node_list: Vec<NodeInfo> = map.into_iter()
                    .map(|v| node_to_node_info(v, local_node_id))
                    .collect();

                let json = node_list.to_json_string_pretty()?;
                println!("{}", json)
            }
            _ => ()
        }
    }
}