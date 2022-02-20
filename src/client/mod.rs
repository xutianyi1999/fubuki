use std::borrow::Borrow;
use std::cell::{Cell, UnsafeCell};
use std::collections::HashSet;
use std::hash::Hash;
use std::io;
use std::iter::Map;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use ahash::RandomState;
use anyhow::{anyhow, Context};
use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use parking_lot::{Mutex, RawRwLock, RwLock};
use parking_lot::lock_api::{RwLockReadGuard, RwLockWriteGuard};
use serde::Serialize;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use tokio::{sync, time};
use tokio::io::BufReader;
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;

use crate::{ClientConfigFinalize, NetworkRangeFinalize, ProtocolMode, TunConfig};
use crate::common::{HashMap, PointerWrap};
use crate::common::net::get_interface_addr;
use crate::common::net::msg_operator::{TCP_BUFF_SIZE, TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, MTU, Node, NodeId, Seq, TcpMsg, UdpMsg};
use crate::common::net::proto::UdpMsg::Heartbeat;
use crate::common::net::SocketExt;
use crate::common::persistence::ToJson;
use crate::common::rc4::Rc4;
use crate::tun::create_device;
use crate::tun::TunDevice;

mod api;

const CHANNEL_SIZE: usize = 100;
static mut LOCAL_NODE_ID: NodeId = 0;
static mut CONFIG: PointerWrap<ClientConfigFinalize> = PointerWrap::default();
static mut MAPPING: PointerWrap<InterfaceMap> = PointerWrap::default();
static mut DIRECT_NODE_LIST: PointerWrap<DirectNodeList> = PointerWrap::default();

fn set_local_node_id(id: NodeId) {
    unsafe { LOCAL_NODE_ID = id }
}

fn get_local_node_id() -> NodeId {
    unsafe { LOCAL_NODE_ID }
}

fn set_config(config: ClientConfigFinalize) {
    unsafe { CONFIG = PointerWrap::new(Box::leak(Box::new(config))) }
}

fn get_config() -> &'static ClientConfigFinalize {
    unsafe { &CONFIG }
}

fn get_mapping() -> &'static InterfaceMap {
    unsafe { &MAPPING }
}

fn get_direct_node_list() -> &'static DirectNodeList {
    unsafe { &DIRECT_NODE_LIST }
}

struct NodeMap<Map> {
    map: Map,
    server_addr: String,
    tcp_handler_channel: Option<Sender<(Box<[u8]>, NodeId)>>,
    udp_socket: Option<Arc<UdpSocket>>,
    key: Rc4,
    try_send_to_lan_addr: bool,
}

struct InterfaceMap {
    // local_addr -> (tun_addr -> node)
    map: HashMap<
        Ipv4Addr,
        NodeMap<RwLock<Arc<HashMap<Ipv4Addr, Node>>>>
    >,
    version: AtomicU8,
}

impl InterfaceMap {
    fn new(map: HashMap<Ipv4Addr, NodeMap<()>>) -> Self {
        let map = map.into_iter()
            .map(|(tun_addr, node_map)| {
                let network_segment = NodeMap {
                    server_addr: node_map.server_addr,
                    map: RwLock::new(Arc::new(HashMap::default())),
                    tcp_handler_channel: node_map.tcp_handler_channel,
                    udp_socket: node_map.udp_socket,
                    key: node_map.key,
                    try_send_to_lan_addr: node_map.try_send_to_lan_addr,
                };
                (tun_addr, network_segment)
            }).collect();

        InterfaceMap {
            map,
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn update(&self, local_tun_addr: &Ipv4Addr, map: HashMap<Ipv4Addr, Node>) {
        let map = Arc::new(map);

        if let Some(segment) = self.map.get(local_tun_addr) {
            *segment.map.write() = map;
            self.version.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn try_load(&self) -> Option<HashMap<
        Ipv4Addr,
        NodeMap<Arc<HashMap<Ipv4Addr, Node>>>
    >> {
        let mut map = HashMap::default();

        for (k, node_map) in &self.map {
            let range = NodeMap {
                server_addr: node_map.server_addr.clone(),
                map: node_map.map.try_read()?.clone(),
                tcp_handler_channel: node_map.tcp_handler_channel.clone(),
                udp_socket: node_map.udp_socket.clone(),
                key: node_map.key.clone(),
                try_send_to_lan_addr: node_map.try_send_to_lan_addr,
            };
            map.insert(*k, range);
        }
        Some(map)
    }
}

macro_rules! init_local_node_mapping {
    () => {
        let mut local_node_mapping: HashMap<Ipv4Addr, NodeMap<Arc<HashMap<Ipv4Addr, Node>>>> = HashMap::default();
        let mut local_node_mapping_version = 0;

        macro_rules! get_local_node_mapping {
            () => {{
                let mapping = get_mapping();
                let mapping_version = mapping.version();

                if mapping_version != local_node_mapping_version {
                    if let Some(v) = mapping.try_load() {
                        local_node_mapping = v;
                        local_node_mapping_version = mapping_version;
                    }
                }
                &local_node_mapping
            }};
        }
    };
}

struct DirectNodeList {
    list: RwLock<HashMap<NodeId, AtomicI64>>,
    version: AtomicU8,
}

impl DirectNodeList {
    fn new() -> Self {
        DirectNodeList {
            list: RwLock::new(HashMap::default()),
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn try_load(&self) -> Option<HashSet<NodeId>> {
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
            self.version.fetch_add(1, Ordering::Relaxed);
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

macro_rules! init_local_direct_node_list {
    () => {
        let mut local_direct_node_list: HashSet<NodeId> = HashSet::new();
        let mut local_direct_node_list_version = 0;

        macro_rules! get_local_direct_node_list {
            () => {{
                let node_list = get_direct_node_list();
                let node_list_version = node_list.version();

                if node_list_version != local_direct_node_list_version {
                    if let Some(v) = node_list.try_load() {
                        local_direct_node_list = v;
                        local_direct_node_list_version = node_list_version
                    }
                }
                &local_direct_node_list
            }};
        }
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

            let mut new = HashMap::default();

            for (k, v) in guard.iter() {
                let time = v.load(Ordering::Relaxed);

                if now - time <= 30 {
                    new.insert(*k, AtomicI64::new(time));
                }
            }
            new
        };
        // TODO 添加flag标志减少update
        get_direct_node_list().try_update_all(new_map)
    }
}

fn tun_handler<T: TunDevice>(tun: &T) -> Result<()> {
    let mut buff = [0u8; MTU];
    let mut out = [0u8; MTU];
    init_local_node_mapping!();
    init_local_direct_node_list!();

    loop {
        let data = match tun.recv_packet(&mut buff).context("Read packet from tun error")? {
            0 => continue,
            len => &buff[..len]
        };

        let ipv4 = Ipv4Packet::new_unchecked(data);

        let Ipv4Address(octets) = ipv4.dst_addr();
        let dst_addr = Ipv4Addr::from(octets);

        let Ipv4Address(octets) = ipv4.src_addr();
        let src_addr = Ipv4Addr::from(octets);

        let mapping: &HashMap<Ipv4Addr, NodeMap<Arc<HashMap<Ipv4Addr, Node>>>> = get_local_node_mapping!();

        let node_map = match mapping.get(&src_addr) {
            Some(v) => v,
            None => continue
        };

        let (local_node, dst_node) = match (node_map.map.get(&src_addr), node_map.map.get(&dst_addr)) {
            (Some(v1), Some(v2)) => (v1, v2),
            _ => continue
        };

        if local_node.mode.udp_support() && dst_node.mode.udp_support() {
            if let Node {
                id: node_id,
                wan_udp_addr: Some(peer_wan_addr),
                lan_udp_addr: Some(peer_lan_addr),
                ..
            } = dst_node {
                let direct_node_list: &HashSet<NodeId> = get_local_direct_node_list!();

                if direct_node_list.contains(node_id) {
                    let peer_addr = if node_map.try_send_to_lan_addr {
                        match node_map.map.get(&src_addr) {
                            Some(Node { wan_udp_addr: Some(local_wan_addr), .. })
                            if local_wan_addr.ip() == peer_wan_addr.ip() => *peer_lan_addr,
                            _ => *peer_wan_addr
                        }
                    } else {
                        *peer_wan_addr
                    };

                    let socket = match node_map.udp_socket {
                        Some(ref v) => &**v,
                        None => unreachable!(),
                    };

                    let msg = UdpMsg::Data(data).encode(&mut out)?;
                    (node_map.key).clone().encrypt_slice(msg);
                    socket.send_to(msg, peer_addr)?;
                    continue;
                }
            }
        }

        if local_node.mode.tcp_support() && dst_node.mode.tcp_support() {
            let tx = match node_map.tcp_handler_channel {
                Some(ref v) => v,
                None => unreachable!()
            };

            if let Err(TrySendError::Closed(_)) = tx.try_send((data.into(), dst_node.id)) {
                return Err(anyhow!("TCP handler channel closed"));
            }
        }
    }
}

async fn heartbeat_schedule(seq: &AtomicU32) -> Result<()> {
    let mut buff = [0u8; MTU];
    init_local_node_mapping!();

    // 网段
    loop {
        let mapping: &HashMap<Ipv4Addr, NodeMap<Arc<HashMap<Ipv4Addr, Node>>>> = get_local_node_mapping!();
        let temp_seq = seq.load(Ordering::Relaxed);

        for (local_tun_addr, segment) in mapping {
            let local_node = match segment.map.get(local_tun_addr) {
                Some(v) => v,
                None => continue
            };

            let socket = match &segment.udp_socket {
                Some(socket) => &*socket,
                None => continue,
            };

            let msg = UdpMsg::Heartbeat(local_node.id, temp_seq, HeartbeatType::Req);
            let out = msg.encode(&mut buff)?;
            segment.key.clone().encrypt_slice(out);
            socket.send_to(out, &segment.server_addr)?;

            for (_, node) in &*segment.map {
                if node.id == local_node.id {
                    continue;
                }

                if let Node {
                    id: node_id,
                    wan_udp_addr: Some(peer_wan_addr),
                    lan_udp_addr: Some(peer_lan_addr),
                    ..
                } = node {
                    let dest_addr = match local_node.wan_udp_addr {
                        Some(local_wan_addr) if local_wan_addr.ip() == peer_wan_addr.ip() => {
                            peer_lan_addr
                        }
                        _ => peer_wan_addr
                    };

                    let heartbeat_packet = UdpMsg::Heartbeat(*node_id, temp_seq, HeartbeatType::Req);
                    let out = heartbeat_packet.encode(&mut buff)?;
                    segment.key.clone().encrypt_slice(out);
                    socket.send_to(out, dest_addr)?;
                }
            }
        }
    }
}

fn mpsc_to_tun<T: TunDevice>(
    mpsc_rx: crossbeam_channel::Receiver<Box<[u8]>>,
    tun: &T,
) -> Result<()> {
    while let Ok(packet) = mpsc_rx.recv() {
        tun.send_packet(&packet).context("Write packet to tun error")?;
    };
    Ok(())
}

fn udp_handler_inner<T: TunDevice>(
    tun: &T,
    socket: &UdpSocket,
    rc4: &Rc4,
    heartbeat_seq: &AtomicU32,
) -> Result<()> {
    let mut buff = [0u8; MTU];

    loop {
        let (len, peer_addr) = socket.recv_from(&mut buff)?;
        let packet = &mut buff[..len];
        rc4.clone().decrypt_slice(packet);

        match UdpMsg::decode(packet)? {
            UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req) if get_local_node_id() == node_id => {
                let resp = UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp);
                let buff = resp.encode(&mut buff)?;
                rc4.clone().encrypt_slice(buff);
                socket.send_to(buff, peer_addr)?;
            }
            // TODO 优化判断
            UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp)
            if node_id != get_local_node_id() && seq == heartbeat_seq.load(Ordering::Relaxed)
            => {
                get_direct_node_list().update(node_id);
            }
            UdpMsg::Data(data) => tun.send_packet(data)?,
            _ => continue
        }
    }
}

fn udp_handler() {}

async fn tcp_handler_inner(
    init_node: Node,
    mut from_tun: Option<Receiver<(Box<[u8]>, NodeId)>>,
    to_tun: Option<crossbeam_channel::Sender<Box<[u8]>>>,
    network_range_info: &NetworkRangeFinalize,
) {
    loop {
        let node = init_node.clone();
        let inner_to_tun = &to_tun;
        let inner_from_tun = &mut from_tun;
        let mut tx_key = network_range_info.key.clone();
        let mut rx_key = network_range_info.key.clone();

        let process = async move {
            let mut stream = TcpStream::connect(&network_range_info.server_addr).await.context("Connect to server error")?;
            info!("Server connected");

            let (rx, mut tx) = stream.split();
            let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

            let mut msg_reader = TcpMsgReader::new(&mut rx, &mut rx_key);
            let mut msg_writer = TcpMsgWriter::new(&mut tx, &mut tx_key);

            let msg = TcpMsg::Register(node);
            msg_writer.write(&msg).await?;
            let msg = msg_reader.read().await?;

            match msg {
                TcpMsg::Result(MsgResult::Success) => (),
                TcpMsg::Result(MsgResult::Timeout) => return Err(anyhow!("Register timeout")),
                _ => return Err(anyhow!("Register error"))
            };

            let (tx, mut rx) = unbounded_channel::<TcpMsg>();

            let latest_recv_heartbeat_time = AtomicI64::new(Utc::now().timestamp());
            let latest_recv_heartbeat_time_ref1 = &latest_recv_heartbeat_time;
            let latest_recv_heartbeat_time_ref2 = &latest_recv_heartbeat_time;

            let seq = AtomicU32::new(0);
            let inner_seq1 = &seq;
            let inner_seq2 = &seq;

            let fut1 = async move {
                loop {
                    match msg_reader.read().await? {
                        TcpMsg::NodeMap(node_map) => {
                            let mapping: HashMap<Ipv4Addr, Node> = node_map.into_iter()
                                .map(|(_, node)| (node.tun_addr, node))
                                .collect();

                            get_mapping().update(&network_range_info.tun.ip, mapping);
                        }
                        TcpMsg::Forward(packet, _) => if let Some(to_tun) = inner_to_tun {
                            to_tun.send(packet.into())?
                        },
                        TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                            let heartbeat = TcpMsg::Heartbeat(seq, HeartbeatType::Resp);
                            tx.send(heartbeat).map_err(|e| anyhow!(e.to_string()))?;
                        }
                        TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                            if inner_seq1.load(Ordering::Relaxed) == recv_seq {
                                latest_recv_heartbeat_time_ref1.store(Utc::now().timestamp(), Ordering::Relaxed)
                            }
                        }
                        _ => continue
                    }
                }

                //TODO define return type
                Ok(())
            };

            let fut2 = async move {
                let mut heartbeat_interval = time::interval(get_config().tcp_heartbeat_interval_secs);
                let mut check_heartbeat_timeout = time::interval(Duration::from_secs(30));

                loop {
                    tokio::select! {
                        opt = rx.recv() => {
                             match opt {
                                Some(heartbeat) => msg_writer.write(&heartbeat).await?,
                                None => return Ok(())
                            }
                        }
                        opt = async {
                            match inner_from_tun {
                                Some(v) => v.recv().await,
                                None => std::future::pending().await
                            }
                        } => {
                            match opt {
                                Some((data, dest_node_id)) => {
                                    let msg = TcpMsg::Forward(&data, dest_node_id);
                                    msg_writer.write(&msg).await?;
                                }
                                None => return Ok(())
                            }
                        }
                        _ = heartbeat_interval.tick() => {
                            let old = inner_seq2.fetch_add(1, Ordering::Relaxed);
                            let heartbeat = TcpMsg::Heartbeat(old + 1, HeartbeatType::Req);
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

            tokio::try_join!(fut1, fut2)
        };

        if let Err(e) = process.await {
            error!("TCP handler error -> {:?}", e)
        }

        time::sleep(Duration::from_secs(3)).await;
    }
}

async fn tcp_handler(
    mut map: HashMap<Ipv4Addr, (Receiver<(Box<[u8]>, NodeId)>, Node)>,
    to_tun: crossbeam_channel::Sender<Box<[u8]>>,
) -> Result<()> {
    let mut handles = Vec::with_capacity(get_config().network_ranges.len());

    for network_range in &get_config().network_ranges {
        let (from_tun, init_node) = match map.remove(&network_range.tun.ip) {
            Some(v) => v,
            None => unreachable!()
        };
        let to_tun = to_tun.clone();

        let h = tokio::spawn(tcp_handler_inner(init_node, Some(from_tun), Some(to_tun), network_range));
        handles.push(h);
    }

    for handle in handles {
        handle.await?;
    }
    Ok(())
}

pub(super) async fn start(config: ClientConfigFinalize) -> Result<()> {
    set_local_node_id(rand::random());
    set_config(config);

    let tun_configs: Vec<TunConfig> = get_config().network_ranges.iter()
        .map(|range| range.tun.clone())
        .collect();

    let tun_device = create_device(&tun_configs).context("Failed create tun adapter")?;
    let tun_device = Arc::new(tun_device);


    Ok(())
}