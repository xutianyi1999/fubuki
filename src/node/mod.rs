use ahash::{HashMap, HashMapExt};
use std::borrow::Cow;
use std::cell::SyncUnsafeCell;
use std::ffi::c_char;
use std::ffi::CString;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use std::{env, slice};

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use ahash::{HashSet, HashSetExt};

use anyhow::Result;
use anyhow::{anyhow, Context as AnyhowContext, Error};
use arc_swap::{ArcSwap, ArcSwapOption, Cache};
use chrono::Utc;
use crossbeam_utils::atomic::AtomicCell;
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use ipnet::Ipv4Net;
use linear_map::LinearMap;
use parking_lot::RwLock;
use rand::{random, Rng, SeedableRng};
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use sys_route::Route;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::TcpSocket;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::mpsc::{unbounded_channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use crate::common::allocator;
use crate::common::allocator::Bytes;
use crate::common::hook::{Hooks, PacketRecvOutput};
use crate::common::net::protocol::{AllocateError, GroupContent, HeartbeatType, NetProtocol, Node, PeerStatus, Register, RegisterError, Seq, TcpMsg, UdpMsg, UdpSocketErr, VirtualAddr, SERVER_VIRTUAL_ADDR, TCP_BUFF_SIZE, TCP_MSG_HEADER_LEN, UDP_BUFF_SIZE, UDP_MSG_HEADER_LEN};
use crate::common::net::{get_ip_dst_addr, get_ip_src_addr, HeartbeatCache, HeartbeatInfo, SocketExt, UdpStatus};
use crate::kcp_bridge::KcpStack;
use crate::node::api::api_start;
use crate::node::sys_route::SystemRouteHandle;
use crate::routing_table::{Item, ItemKind, RoutingTable};
use crate::tun::TunDevice;
use crate::{common, routing_table, Cipher, Context, NodeConfigFinalize, ProtocolMode, TargetGroupFinalize};

mod api;
#[cfg(feature = "cross-nat")]
mod cross_nat;
#[cfg_attr(any(target_os = "windows", target_os = "linux", target_os = "macos"), path = "sys_route.rs")]
#[cfg_attr(not(any(target_os = "windows", target_os = "linux", target_os = "macos")), path = "fake_sys_route.rs")]
mod sys_route;
mod info_tui;

type NodeList = Vec<ExtendedNode>;

trait NodeListOps {
    fn get_node(&self, addr: &VirtualAddr) -> Option<&ExtendedNode>;
}

impl NodeListOps for NodeList {
    fn get_node(&self, addr: &VirtualAddr) -> Option<&ExtendedNode> {
        self.binary_search_by_key(addr, |node| node.node.virtual_addr)
            .ok()
            .map(|v| &self[v])
    }
}

enum RoutingTableEnum<A, B> {
    Internal(ArcSwap<A>),
    External(SyncUnsafeCell<B>)
}

enum RoutingTableRefEnum<'a, A, B> {
    Cache(Cache<&'a ArcSwap<A>, Arc<A>>),
    Ref(&'a SyncUnsafeCell<B>)
}

impl <'a, A, B> From<&'a RoutingTableEnum<A, B>> for RoutingTableRefEnum<'a, A, B> {
    fn from(value: &'a RoutingTableEnum<A, B>) -> Self {
        match value {
            RoutingTableEnum::Internal(v) => RoutingTableRefEnum::Cache(Cache::new(v)),
            RoutingTableEnum::External(v) => RoutingTableRefEnum::Ref(v)
        }
    }
}

struct AtomicAddr {
    inner: AtomicU32
}

impl AtomicAddr {
    fn load(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.inner.load(Ordering::Relaxed))
    }

    fn store(&self, addr: Ipv4Addr) {
        self.inner.store(u32::from_be_bytes(addr.octets()), Ordering::Relaxed)
    }
}

impl From<Ipv4Addr> for AtomicAddr {
    fn from(value: Ipv4Addr) -> Self {
        let inner = AtomicU32::new(u32::from_be_bytes(value.octets()));

        AtomicAddr {
            inner
        }
    }
}

struct AtomicCidr {
    inner: AtomicU64
}

#[repr(align(8))]
struct Inner {
    v: Ipv4Net
}

impl From<Ipv4Net> for AtomicCidr {
    fn from(value: Ipv4Net) -> Self {
        let inner= unsafe {
            AtomicU64::new(std::mem::transmute(Inner { v: value }))
        };

        AtomicCidr {
            inner
        }
    }
}

impl AtomicCidr {
    fn load(&self) -> Ipv4Net {
        let inner: Inner = unsafe {
            std::mem::transmute(self.inner.load(Ordering::Relaxed))
        };
        inner.v
    }

    fn store(&self, cidr: Ipv4Net) {
        let v: u64 = unsafe {
            std::mem::transmute(Inner { v: cidr })
        };

        self.inner.store(v, Ordering::Relaxed)
    }
}

pub struct Interface<K> {
    index: usize,
    node_name: String,
    group_name: ArcSwapOption<String>,
    addr: AtomicAddr,
    cidr: AtomicCidr,
    mode: ProtocolMode,
    specify_mode: LinearMap<VirtualAddr, ProtocolMode>,
    node_list: ArcSwap<NodeList>,
    server_addr: String,
    server_udp_hc: RwLock<HeartbeatCache>,
    server_udp_status: AtomicCell<UdpStatus>,
    server_tcp_hc: RwLock<HeartbeatCache>,
    server_is_connected: AtomicBool,
    server_allow_udp_relay: AtomicBool,
    server_allow_tcp_relay: AtomicBool,
    tcp_handler_channel: Option<Sender<Bytes>>,
    udp_socket: Option<UdpSocket>,
    key: K,
    peers_map: Option<RwLock<HashMap<VirtualAddr, Vec<PeerStatus>>>>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InterfaceInfo {
    index: usize,
    node_name: String,
    group_name: Option<String>,
    addr: VirtualAddr,
    cidr: Ipv4Net,
    mode: ProtocolMode,
    node_map: HashMap<VirtualAddr, ExtendedNodeInfo>,
    server_addr: String,
    server_udp_hc: HeartbeatInfo,
    server_udp_status: UdpStatus,
    server_tcp_hc: HeartbeatInfo,
    server_is_connected: bool,
}

impl <K> From<&Interface<K>> for InterfaceInfo {
    fn from(value: &Interface<K>) -> Self {
        InterfaceInfo {
            index: value.index,
            node_name: value.node_name.clone(),
            group_name: {
                value.group_name
                    .load()
                    .as_ref()
                    .map(|v| (**v).clone())
            },
            addr: value.addr.load(),
            cidr: value.cidr.load(),
            mode: value.mode.clone(),
            node_map: {
                value.node_list
                    .load_full()
                    .iter()
                    .map(|node| {
                        (node.node.virtual_addr, ExtendedNodeInfo::from(node))
                    })
                    .collect()
            },
            server_addr: value.server_addr.clone(),
            server_udp_hc: HeartbeatInfo::from(&*value.server_udp_hc.read()),
            server_udp_status: value.server_udp_status.load(),
            server_tcp_hc: HeartbeatInfo::from(&*value.server_tcp_hc.read()),
            server_is_connected: value.server_is_connected.load(Ordering::Relaxed)
        }
    }
}

struct ExtendedNode {
    pub node: Node,
    pub udp_status: Arc<AtomicCell<UdpStatus>>,
    pub hc: Arc<RwLock<HeartbeatCache>>,
    pub peer_addr: Arc<AtomicCell<Option<SocketAddr>>>
}

impl From<Node> for ExtendedNode {
    fn from(node: Node) -> Self {
        ExtendedNode {
            node,
            udp_status: Arc::new(AtomicCell::new(UdpStatus::Unavailable)),
            hc: Arc::new(RwLock::new(HeartbeatCache::new())),
            peer_addr: Arc::new(AtomicCell::new(None))
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct ExtendedNodeInfo {
    node: Node,
    udp_status: UdpStatus,
    hc: HeartbeatInfo,
}

impl From<&ExtendedNode> for ExtendedNodeInfo {
    fn from(value: &ExtendedNode) -> Self {
        ExtendedNodeInfo {
            node: value.node.clone(),  
            udp_status: value.udp_status.load(),
            hc: HeartbeatInfo::from(&*value.hc.read())
        }
    }
}

async fn lookup_host(dst: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(dst).await.ok()?.next()
}

#[derive(Clone, Copy, Debug)]
struct NextHop {
    next: VirtualAddr,
    cost: u64
}

fn find_next_hop(
    curr: VirtualAddr,
    dst: VirtualAddr,
    cache: &mut Vec<(VirtualAddr, Option<NextHop>, Instant)>,
    peers: &RwLock<HashMap<VirtualAddr, Vec<PeerStatus>>>
) -> Option<NextHop> {
    fn find(
        curr: VirtualAddr,
        dst: VirtualAddr,
        peers: &HashMap<VirtualAddr, Vec<PeerStatus>>
    ) -> Option<NextHop> {
        use pathfinding::prelude::dijkstra;
        const EMPTY: &'static Vec<PeerStatus> = &Vec::new();

        let route = dijkstra(
            &curr, 
            |ip| {
                let peers_status_list = peers.get(ip).unwrap_or(EMPTY);
                let mut peers = Vec::with_capacity(peers_status_list.len());
                
                for peer_status in peers_status_list {
                    if let (Some(latency), Some(packet_loss)) = (peer_status.latency, peer_status.packet_loss) {
                        // normalization
                        // 200 ms
                        let latency_quality = (latency.as_millis() as u64 * 100) / 200;
                        // 3% packet loss
                        let packet_loss_quality = (packet_loss as u64 * 100) / 3;
                        peers.push((peer_status.addr, latency_quality + packet_loss_quality));
                    }
                }
                peers
            }, 
            |&ip| ip == dst
        );

        match route {
            Some((route, cost)) => {
                info!("select route {:?} for dest addr {}, cost: {}", route, dst, cost);
                // routing sequence starts from the current address, index 1 is the next hop.
                Some(NextHop{next: route[1], cost })
            },
            None => None
        }
    }

    match cache.binary_search_by_key(&dst, |(addr, _, _)| *addr) {
        Ok(i) => {
            let (_, next_hop, update_time) = &cache[i];

            if update_time.elapsed() < Duration::from_secs(60) {
                return *next_hop;
            }

            let new = find(curr, dst, &peers.read());
            let (_, old, t) = &mut cache[i];
            *old = new;
            *t = Instant::now();
            new
        }
        Err(i) => {
            let next = find(curr, dst, &peers.read());
            cache.insert(i, (dst, next, Instant::now()));
            next
        }
    }
}

async fn send<K: Cipher>(
    nonce: u16,
    inter: &Interface<K>,
    dst_node: &ExtendedNode,
    buff: &mut [u8],
    packet_range: Range<usize>,
    node_relay: bool,
    next_route_cache: &mut Vec<(VirtualAddr, Option<NextHop>, Instant)>,
    node_list: &NodeList
) -> Result<()> {
    let mode = inter.specify_mode.get(&dst_node.node.virtual_addr).unwrap_or(&inter.mode);

    macro_rules! relay_packet_through_node {
        ($max_cost: expr) => {
            if node_relay {
                if let Some(peers_map) = &inter.peers_map {
                    let next = find_next_hop(inter.addr.load(), dst_node.node.virtual_addr, next_route_cache, peers_map);
        
                    if let Some(next) = next {
                        if next.next != dst_node.node.virtual_addr && next.cost < $max_cost {
                            if let Some(node) = node_list.get_node(&next.next) {
                                if let UdpStatus::Available { dst_addr } = node.udp_status.load() {
                                    let socket = match &inter.udp_socket {
                                        None => unreachable!(),
                                        Some(socket) => socket,
                                    };
                        
                                    let packet = &mut buff[packet_range.start - size_of::<VirtualAddr>() - UDP_MSG_HEADER_LEN..packet_range.end];
                                    UdpMsg::relay_encode(&inter.key, nonce, dst_node.node.virtual_addr, packet_range.len(), packet);
                        
                                    match UdpMsg::send_msg(socket, packet, dst_addr).await {
                                        Ok(_) => return Ok(()),
                                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                                        Err(UdpSocketErr::SuppressError(e)) => {
                                            warn!("node {} send udp packet warn {}", inter.node_name, e);
                                        }
                                    };
                                }
                            }
                        }
                    }
                }
            }
        };
    }

    let support_p2p = (!mode.p2p.is_empty()) && (!dst_node.node.mode.p2p.is_empty());

    if support_p2p {
        relay_packet_through_node!(200);

        let udp_status = dst_node.udp_status.load();

        if let UdpStatus::Available { dst_addr } = udp_status {
            debug!("PacketSender: udp message p2p to node {}", dst_node.node.name);

            let socket = match &inter.udp_socket {
                None => unreachable!(),
                Some(socket) => socket,
            };

            let packet = &mut buff[packet_range.start - UDP_MSG_HEADER_LEN..packet_range.end];
            UdpMsg::data_encode(&inter.key, nonce, packet_range.len(), packet);

            match UdpMsg::send_msg(socket, packet, dst_addr).await {
                Ok(_) => return Ok(()),
                Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                Err(UdpSocketErr::SuppressError(e)) => {
                    warn!("node {} send udp packet warn {}", inter.node_name, e);
                }
            };
        }

        relay_packet_through_node!(300);
    }

    if (!mode.relay.is_empty()) && (!dst_node.node.mode.relay.is_empty()) {
        for np in &mode.relay {
            match np {
                NetProtocol::TCP if inter.server_allow_tcp_relay.load(Ordering::Relaxed) => {
                    let tx = match inter.tcp_handler_channel {
                        None => unreachable!(),
                        Some(ref v) => v,
                    };

                    const DATA_START: usize = TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>();
                    let mut packet = allocator::alloc(DATA_START + packet_range.len());
                    packet[DATA_START..].copy_from_slice(&buff[packet_range.start..packet_range.end]);

                    TcpMsg::relay_encode(&inter.key, nonce, dst_node.node.virtual_addr, packet_range.len(), &mut packet);

                    match tx.try_send(packet) {
                        Ok(_) => {
                            debug!("PacketSender: tcp message relay to node {}", dst_node.node.name);
                            return Ok(());
                        },
                        Err(e) => error!("PacketSender: tunnel error: {}", e)
                    }
                }
                NetProtocol::UDP if inter.server_allow_udp_relay.load(Ordering::Relaxed) => {
                    let socket = match &inter.udp_socket {
                        None => unreachable!(),
                        Some(socket) => socket,
                    };

                    let dst_addr = match inter.server_udp_status.load() {
                        UdpStatus::Available { dst_addr } => dst_addr,
                        UdpStatus::Unavailable => continue,
                    };

                    debug!("PacketSender: udp message relay to node {}", dst_node.node.name);

                    let packet = &mut buff[packet_range.start - size_of::<VirtualAddr>() - UDP_MSG_HEADER_LEN..packet_range.end];

                    UdpMsg::relay_encode(&inter.key, nonce, dst_node.node.virtual_addr, packet_range.len(), packet);

                    match UdpMsg::send_msg(socket, packet, dst_addr).await {
                        Ok(_) => return Ok(()),
                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                        Err(UdpSocketErr::SuppressError(e)) => {
                            warn!("node {} send udp packet warn {}", inter.node_name, e);
                        }
                    };
                }
                _ => ()
            };
        }
    }

    if support_p2p {
        relay_packet_through_node!(500);
    }

    warn!("no route to {}", dst_node.node.name);
    Ok(())
}

enum TransferType {
    Unicast(VirtualAddr),
    Broadcast,
}

#[allow(unused)]
fn find_once<RT: RoutingTable>(rt: &RT, src_addr: Ipv4Addr, dst_addr: Ipv4Addr) -> Option<Cow<'_, Item>>{
    rt.find(src_addr, dst_addr)
}

fn find_route<RT: RoutingTable>(rt: &RT, src_addr: Ipv4Addr, mut dst_addr: Ipv4Addr) -> Option<(Ipv4Addr, Cow<'_, Item>)> {
    let mut item = rt.find(src_addr, dst_addr)?;
    let mut count = 1;

    // is route on link
    while item.gateway != Ipv4Addr::UNSPECIFIED {
        // too many hops, possibly loop routing
        if count > 5 {
            return None;
        }
        
        dst_addr = item.gateway;
        item = rt.find(src_addr, dst_addr)?;

        count += 1;
    }
    Some((dst_addr, item))
}

struct PacketSender<'a, InterRT, ExternRT, Tun, K> {
    rt_ref: RoutingTableRefEnum<'a, InterRT, ExternRT>,
    interfaces: &'a [&'a Interface<K>],
    nodes_cache: Vec<Cache<&'a ArcSwap<NodeList>, Arc<NodeList>>>,
    tun: &'a Tun,
    hooks: Option<&'a Hooks<K>>,
    #[cfg(feature = "cross-nat")]
    snat: Option<&'a cross_nat::SNat>,
    rng: rand::rngs::SmallRng,
    // if_index -> (dst addr, next hop, update time)
    next_route: Vec<Vec<(VirtualAddr, Option<NextHop>, Instant)>>
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Output,
    Input
}

impl <'a, InterRT, ExternRT, Tun, K> PacketSender<'a, InterRT, ExternRT, Tun, K>
    where
        InterRT: RoutingTable,
        ExternRT: RoutingTable,
        Tun: TunDevice,
        K: Cipher
{
    fn new(
        rt: &'a RoutingTableEnum<InterRT, ExternRT>,
        interfaces: &'a [&'a Interface<K>],
        tun: &'a Tun,
        hooks: Option<&'a Hooks<K>>,
        #[cfg(feature = "cross-nat")]
        snat: Option<&'a cross_nat::SNat>
    ) -> Self {
        PacketSender {
            rt_ref: RoutingTableRefEnum::from(rt),
            interfaces,
            nodes_cache: interfaces.iter().map(|v| Cache::new(&v.node_list)).collect::<Vec<_>>(),
            tun,
            hooks,
            #[cfg(feature = "cross-nat")]
            snat,
            rng: rand::rngs::SmallRng::from_os_rng(),
            next_route: vec![Vec::new(); interfaces.len()]
        }
    }

    async fn send_packet(
        &mut self,
        direction: Direction,
        packet_range: Range<usize>,
        buff: &mut [u8],
        allow_packet_forward: bool,
        allow_packet_not_in_rules_send_to_kernel: bool,
        relay_dst_addr: Option<VirtualAddr>
    ) -> Result<()> {
        let interfaces = self.interfaces;

        let packet = &mut buff[packet_range.clone()];

        let (Ok(src_addr), Ok(mut dst_addr)) = (get_ip_src_addr(packet), get_ip_dst_addr(packet)) else {
            error!("Illegal ipv4 packet");
            return Ok(());
        };

        if let Some(hooks) = self.hooks {
            let output = hooks.packet_recv(direction, packet);

            if output == PacketRecvOutput::Drop {
                return Ok(());
            }
        }

        #[cfg(feature = "cross-nat")]
        if let Some(snat) = self.snat {
            let item = match &mut self.rt_ref {
                RoutingTableRefEnum::Cache(v) => find_once(&**v.load(), src_addr, dst_addr),
                RoutingTableRefEnum::Ref(v) => unsafe { find_once(&*v.get(), src_addr, dst_addr) }
            };

            if item.and_then(|i| i.extend.item_kind) == Some(ItemKind::AllowedIpsRoute) {
                return snat.input(&buff[packet_range]).await;
            }
        }

        macro_rules! find_route_with_dst {
            ($dst_addr: expr) => {
                match &mut self.rt_ref {
                    RoutingTableRefEnum::Cache(v) => find_route(&**v.load(), src_addr, $dst_addr),
                    RoutingTableRefEnum::Ref(v) => unsafe { find_route(&*v.get(), src_addr, $dst_addr) }
                }
            };
        }

        let mut opt = find_route_with_dst!(dst_addr);

        if opt.is_none() {
            if let Some(relay_dst_addr) = relay_dst_addr {
                dst_addr = relay_dst_addr;
                opt = find_route_with_dst!(dst_addr);
            }
        }

        let (dst_addr, item) = match opt {
            None => {
                if direction == Direction::Input && allow_packet_not_in_rules_send_to_kernel {
                    self.tun.send_packet(&buff[packet_range]).await.context("error send packet to tun")?;
                }

                debug!("PacketSender: cannot find route {}->{}", src_addr, dst_addr);
                return Ok(())
            },
            Some(v) => v,
        };

        let if_index = item.interface_index;

        let (interface, node_list, next_route_cache) = match interfaces.iter().position(|i| i.index == if_index) {
            Some(i) => (interfaces[i], &**self.nodes_cache[i].load(), &mut self.next_route[i]),
            None => return Ok(())
        };

        let interface_addr = interface.addr.load();
        let interface_cidr = interface.cidr.load();

        if !interface.server_is_connected.load(Ordering::Relaxed) {
            return Ok(())
        }

        let transfer_type = if dst_addr.is_broadcast() {
            if direction == Direction::Output && interface_addr != src_addr {
                return Ok(())
            }

            if direction == Direction::Input && !interface_cidr.contains(&src_addr) {
                return Ok(())
            }

            TransferType::Broadcast
        } else if interface_cidr.broadcast() == dst_addr {
            TransferType::Broadcast
        } else {
            TransferType::Unicast(dst_addr)
        };

        match transfer_type {
            TransferType::Unicast(addr) => {
                debug!("PacketSender: packet {}->{}; gateway: {}", src_addr, dst_addr, addr);

                if interface_addr == addr {
                    return self.tun.send_packet(&buff[packet_range]).await.context("error send packet to tun");
                }

                let f = match direction {
                    Direction::Output => true,
                    Direction::Input if allow_packet_forward => true,
                    _ => false,
                };

                if f {
                    match node_list.get_node(&addr) {
                        None => warn!("cannot find node {}", addr),
                        Some(node) => send(
                            self.rng.random(),
                            interface, 
                            node,
                            buff,
                            packet_range,
                            true,
                            next_route_cache,
                            node_list
                        ).await?
                    };
                }
            }
            TransferType::Broadcast => {
                debug!("PacketSender: packet {}->{}; broadcast", src_addr, dst_addr);

                match direction {
                    Direction::Output => {
                        for node in node_list {
                            if node.node.virtual_addr == interface_addr {
                                continue;
                            }

                            send(
                                self.rng.random(),
                                interface, 
                                node, 
                                buff, 
                                packet_range.clone(),
                                false,
                                next_route_cache,
                                node_list
                            ).await?;
                        }
                    }
                    Direction::Input => {
                        self.tun.send_packet(&buff[packet_range]).await.context("error send packet to tun")?;
                    }
                }
            }
        }
        Ok(())
    }
}

async fn tun_handler<T, K, InterRT, ExternRT>(
    tun: T,
    routing_table: Arc<RoutingTableEnum<InterRT, ExternRT>>,
    interfaces: Vec<Arc<Interface<K>>>,
    hooks: Option<Arc<Hooks<K>>>,
    #[cfg(feature = "cross-nat")]
    snat: Option<Arc<cross_nat::SNat>>
) -> Result<()>
    where
        T: TunDevice + Clone + Send + Sync + 'static,
        K: Cipher + Clone + Send + Sync + 'static,
        InterRT: RoutingTable + Send + Sync + 'static,
        ExternRT: RoutingTable + Send + Sync + 'static
{
    let mut futs = Vec::new();

    for _ in 0..2 {
        let fut = async {
            let tun = tun.clone();
            let routing_table = routing_table.clone();
            let interfaces = interfaces.clone();
            let hooks = hooks.clone();
            #[cfg(feature = "cross-nat")]
            let snat = snat.clone();

            let join: JoinHandle<Result<()>> = tokio::spawn(async move {
                let interfaces = interfaces.iter().map(|v| &**v).collect::<Vec<_>>();

                let mut sender = PacketSender::new(
                    &*routing_table,
                    &interfaces,
                    &tun,
                    hooks.as_deref(),
                    #[cfg(feature = "cross-nat")]
                    snat.as_deref()
                );

                let mut buff = vec![0u8; UDP_BUFF_SIZE];

                loop {
                    const START: usize = UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>();

                    let packet_range = match tun
                        .recv_packet(&mut buff[START..])
                        .await
                        .context("error receive packet from tun")?
                    {
                        0 => continue,
                        len => START..START + len,
                    };

                    sender.send_packet(
                        Direction::Output,
                        packet_range,
                        &mut buff,
                        true,
                        false,
                        None
                    ).await?;
                }
            });
            join.await?
        };

        futs.push(fut);
    }
    
    futures_util::future::try_join_all(futs).await.context("tun handler error")?;
    Ok(())
}

fn through_virtual_gateway<RT: RoutingTable + ?Sized>(routing_table: &RT, src: SocketAddr, dst: SocketAddr) -> bool {
    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
           routing_table.find(*src.ip(), *dst.ip()).is_some_and(|i| i.extend.item_kind != Some(ItemKind::AllowedIpsRoute))
        }
        _ => false
    }
}

async fn udp_handler<T, K, InterRT, ExternRT>(
    config: &'static NodeConfigFinalize<K>,
    group: &'static TargetGroupFinalize<K>,
    table: Arc<RoutingTableEnum<InterRT, ExternRT>>,
    interface: Arc<Interface<K>>,
    tun: T,
    hooks: Option<Arc<Hooks<K>>>,
    #[cfg(feature = "cross-nat")]
    snat: Option<Arc<cross_nat::SNat>>,
    kcpstack_tx: Option<tokio::sync::mpsc::Sender<Bytes>>
) -> Result<()>
where
    T: TunDevice + Clone + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
    InterRT: RoutingTable + Send + Sync + 'static,
    ExternRT: RoutingTable + Send + Sync + 'static
{
    let lan_ip_addr = group.lan_ip_addr.unwrap();

    let heartbeat_schedule = async {
        let interface = interface.clone();
        let table = table.clone();

        let join = tokio::spawn(async move {
            let mut rng = rand::rngs::SmallRng::from_os_rng();
            let socket = interface.udp_socket.as_ref().expect("must need udp socket");
            let key = &interface.key;
            let is_p2p = interface.mode.p2p.contains(&NetProtocol::UDP);
            let mut packet = [0u8; UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + size_of::<Seq>() + size_of::<HeartbeatType>()];

            loop {
                let interface_addr = interface.addr.load();

                if interface.server_is_connected.load(Ordering::Relaxed) {
                    let server_hc = &interface.server_udp_hc;
                    let seq = {
                        let mut server_hc_guard = server_hc.write();
                        server_hc_guard.check();

                        if server_hc_guard.packet_continuous_loss_count >= config.udp_heartbeat_continuous_loss &&
                            interface.server_udp_status.load() != UdpStatus::Unavailable
                        {
                            interface.server_udp_status.store(UdpStatus::Unavailable);
                        }

                        server_hc_guard.ping();
                        server_hc_guard.seq
                    };

                    UdpMsg::heartbeat_encode(
                        key,
                        rng.random(),
                        interface_addr,
                        seq,
                        HeartbeatType::Req,
                        &mut packet,
                    );

                    match UdpMsg::send_msg(socket, &packet, &interface.server_addr).await {
                        Ok(_) => (),
                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                        Err(UdpSocketErr::SuppressError(e)) => {
                            warn!("node {} send udp packet warn {}", group.node_name, e);
                        }
                    }

                    if is_p2p {
                        let node_list = interface.node_list.load_full();

                        for ext_node in node_list.as_slice() {
                            if !ext_node.node.mode.p2p.contains(&NetProtocol::UDP) {
                                continue;
                            }

                            let is_over: bool;
                            let udp_status = ext_node.udp_status.load();

                            let seq = {
                                let mut hc = ext_node.hc.write();
                                hc.check();
                                is_over = hc.packet_continuous_loss_count >= config.udp_heartbeat_continuous_loss;

                                if is_over && udp_status != UdpStatus::Unavailable {
                                    ext_node.udp_status.store(UdpStatus::Unavailable);
                                }

                                if ext_node.node.lan_udp_addr.is_none() ||
                                    ext_node.node.wan_udp_addr.is_none()
                                {
                                    continue;
                                }

                                hc.ping();
                                hc.seq
                            };

                            UdpMsg::heartbeat_encode(
                                key,
                                rng.random(),
                                interface_addr, 
                                seq, 
                                HeartbeatType::Req, 
                                &mut packet
                            );

                            match udp_status {
                                UdpStatus::Available { dst_addr } if !is_over => {
                                    match UdpMsg::send_msg(socket, &packet, dst_addr).await {
                                        Ok(_) => (),
                                        Err(UdpSocketErr::FatalError(e)) => return Result::<(), _>::Err(anyhow!(e)),
                                        Err(UdpSocketErr::SuppressError(e)) => {
                                            warn!("node {} send udp packet warn {}", group.node_name, e);
                                        }
                                    };
                                }
                                _ => {
                                    if let (Some(lan), Some(wan)) = (ext_node.node.lan_udp_addr, ext_node.node.wan_udp_addr) {
                                        let addr = ext_node.peer_addr.load();

                                        let packet = packet.as_slice();
                                        let t;

                                        let rt: &(dyn RoutingTable + Sync) = match &*table {
                                            RoutingTableEnum::Internal(v) => {
                                                t = v.load_full();
                                                &*t
                                            },
                                            RoutingTableEnum::External(v) => unsafe { &*v.get() }
                                        };
                                        
                                        macro_rules! send {
                                            ($peer_addr: expr) => {
                                                // Android VPNService should add itself to addDisallowedApplication
                                                if (config.socket_bind_device.is_some() || cfg!(target_os = "android"))||
                                                !through_virtual_gateway(rt, SocketAddr::new(lan_ip_addr, 0), $peer_addr) 
                                                {
                                                    match UdpMsg::send_msg(socket, &packet, $peer_addr).await {
                                                        Ok(_) => (),
                                                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                                                        Err(UdpSocketErr::SuppressError(e)) => {
                                                            warn!("node {} send udp packet warn {}", group.node_name, e);
                                                        }
                                                    };
                                                }
                                            };
                                        }

                                        if let Some(addr) = addr {
                                            if addr != lan && addr != wan {
                                                send!(addr);
                                            }
                                        }

                                        if wan == lan {
                                            send!(wan);
                                        } else {
                                            send!(lan);
                                            send!(wan);
                                        }
                                    }
                                }
                            };
                        }
                    }
                }

                time::sleep(config.udp_heartbeat_interval).await
            }
        });

        join.await?
    };


    let mut recv_futs = Vec::new();

    for _ in 0..2 {
        let recv_handler = async {
            let interface = interface.clone();
            let table = table.clone();
            let tun = tun.clone();
            let hooks = hooks.clone();
            #[cfg(feature = "cross-nat")]
            let snat = snat.clone();

            let kcpstack_tx = kcpstack_tx.clone();

            let join = tokio::spawn(async move {
                let mut rng = rand::rngs::SmallRng::from_os_rng();
                let socket = interface.udp_socket.as_ref().expect("must need udp socket");
                let key = &interface.key;
                let is_p2p = interface.mode.p2p.contains(&NetProtocol::UDP);

                let arr = [interface.as_ref()];
                let mut sender = PacketSender::new(
                    &*table, 
                    &arr, 
                    &tun, 
                    hooks.as_deref(), 
                    #[cfg(feature = "cross-nat")]
                    snat.as_deref()
                );
                let mut buff = vec![0u8; UDP_BUFF_SIZE];

                loop {
                    const START: usize = size_of::<VirtualAddr>();

                    let (len, peer_addr) = match UdpMsg::recv_msg(socket, &mut buff[START..]).await {
                        Ok(v) => v,
                        Err(UdpSocketErr::SuppressError(e)) => {
                            warn!("node {} receive udp packet warn {}", group.node_name, e);
                            continue;
                        }
                        Err(UdpSocketErr::FatalError(e)) => return Result::<(), _>::Err(anyhow!(e))
                    };

                    let packet = &mut buff[START..START + len];

                    if let Ok(packet) = UdpMsg::decode(key, packet) {
                        match packet {
                            UdpMsg::Heartbeat(from_addr, seq, HeartbeatType::Req) => {
                                let mut is_known = false;

                                if from_addr == SERVER_VIRTUAL_ADDR {
                                    is_known = true;
                                } else if is_p2p {
                                    if let Some(en) = interface.node_list.load().get_node(&from_addr) {
                                        let old = en.peer_addr.load();

                                        if old != Some(peer_addr) {
                                            en.peer_addr.store(Some(peer_addr));
                                        }
                                        is_known = true;
                                    }
                                }

                                if is_known {
                                    let interface_addr = interface.addr.load();

                                    let len = UdpMsg::heartbeat_encode(
                                        key,
                                        rng.random(),
                                        interface_addr,
                                        seq,
                                        HeartbeatType::Resp,
                                        &mut buff,
                                    );

                                    let packet = &mut buff[..len];

                                    match UdpMsg::send_msg(socket, packet, peer_addr).await {
                                        Ok(_) => (),
                                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                                        Err(UdpSocketErr::SuppressError(e)) => {
                                            warn!("node {} send udp packet warn {}", group.node_name, e);
                                        }
                                    };
                                }
                            }
                            UdpMsg::Heartbeat(from_addr, seq, HeartbeatType::Resp) => {
                                if from_addr == SERVER_VIRTUAL_ADDR {
                                    let udp_status = interface.server_udp_status.load();

                                    match udp_status {
                                        UdpStatus::Available { dst_addr } => {
                                            if dst_addr == peer_addr {
                                                interface.server_udp_hc.write().reply(seq);
                                                continue;
                                            }

                                            if lookup_host(&interface.server_addr).await == Some(peer_addr) {
                                                if interface.server_udp_hc.write().reply(seq).is_some() {
                                                    interface.server_udp_status.store(UdpStatus::Available {dst_addr: peer_addr});
                                                }
                                            }
                                        }
                                        UdpStatus::Unavailable => {
                                            if lookup_host(&interface.server_addr).await == Some(peer_addr)  {
                                                let mut server_hc_guard = interface.server_udp_hc.write();

                                                if server_hc_guard.reply(seq).is_some() &&
                                                    server_hc_guard.packet_continuous_recv_count >= config.udp_heartbeat_continuous_recv
                                                {
                                                    drop(server_hc_guard);
                                                    interface.server_udp_status.store(UdpStatus::Available {dst_addr: peer_addr});
                                                }
                                            }
                                        }
                                    };
                                } else if is_p2p {
                                    if let Some(node) = interface.node_list.load_full().get_node(&from_addr) {
                                        let mut hc_guard = node.hc.write();

                                        if hc_guard.reply(seq).is_some() {
                                            let through_vgateway = || {
                                                let src = SocketAddr::new(lan_ip_addr, 0);

                                                match &*table {
                                                    RoutingTableEnum::Internal(v) => through_virtual_gateway(&**v.load(), src, peer_addr),
                                                    RoutingTableEnum::External(v) => through_virtual_gateway(unsafe { &*v.get() }, src, peer_addr)
                                                }
                                            };

                                            if node.udp_status.load() == UdpStatus::Unavailable &&
                                                hc_guard.packet_continuous_recv_count >= config.udp_heartbeat_continuous_recv &&
                                                ((config.socket_bind_device.is_some() || cfg!(target_os = "android"))||
                                                    !through_vgateway()
                                                )
                                            {
                                                drop(hc_guard);

                                                node.udp_status.store(UdpStatus::Available {
                                                    dst_addr: peer_addr,
                                                });
                                            }
                                        }
                                    }
                                };
                            }
                            // todo forward packet ttl minus one
                            UdpMsg::Data(_) => {
                                const START_DATA: usize = START + UDP_MSG_HEADER_LEN;
                                sender.send_packet(
                                    Direction::Input,
                                    START_DATA..START_DATA + len,
                                    &mut buff,
                                    config.allow_packet_forward,
                                    config.allow_packet_not_in_rules_send_to_kernel,
                                    None,
                                ).await?;
                            }
                            UdpMsg::Relay(dst, _) => {
                                const START_DATA: usize = START + UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>();
                                sender.send_packet(
                                    Direction::Input,
                                    START_DATA..START_DATA + len,
                                    &mut buff,
                                    config.allow_packet_forward,
                                    config.allow_packet_not_in_rules_send_to_kernel,
                                    Some(dst)
                                ).await?;
                            }
                            UdpMsg::KcpData(data) => {
                                if let Some(tx) = &kcpstack_tx {
                                    let mut packet = allocator::alloc(data.len());
                                    packet.copy_from_slice(data);
                                    let _ = tx.try_send(packet);
                                }
                            }
                        }
                    }
                }
            });

            join.await?
        };

        recv_futs.push(recv_handler);
    }

    tokio::try_join!(heartbeat_schedule, futures_util::future::try_join_all(recv_futs)).with_context(|| format!("node {} udp handler error", group.node_name))?;
    Ok(())
}

#[derive(Clone, Copy)]
enum RegisterVirtualAddr {
    Manual((VirtualAddr, Ipv4Net)),
    Auto(Option<(VirtualAddr, Ipv4Net)>),
}

async fn register<K>(
    group: &'static TargetGroupFinalize<K>,
    interface: Arc<Interface<K>>,
    key: &K,
    register_addr: &mut RegisterVirtualAddr,
    lan_udp_socket_addr: Option<SocketAddr>,
    refresh_route: &mut bool,
    socket_bind_device: Option<&str>,
    kcp_stack_rx: Option<Arc<tokio::sync::Mutex<Receiver<Bytes>>>>,
) -> Result<((Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>), GroupContent)>
where
    K: Cipher + Clone + Send + Sync
{
    let server_addr = lookup_host(&group.server_addr)
        .await
        .ok_or_else(|| anyhow!("failed to resolve server {}", group.server_addr))?;

    let (mut reader, mut writer): (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) = if group.use_kcp_session {
        let (handler_kcp_channel_from_tcp, handler_kcp_channel_from_kcp) = tokio::io::duplex(8192);
        let kcp_stack_rx = kcp_stack_rx.unwrap();

        tokio::spawn(async move {
            let socket = interface.udp_socket.as_ref().expect("must need udp socket");
            let mut kcp_stack_rx_guard = kcp_stack_rx.lock().await;
            let kcp_stack_rx = &mut *kcp_stack_rx_guard;

            let conv = rand::random();
            let (mut rx, mut tx) = tokio::io::split(handler_kcp_channel_from_kcp);

            let mut stack = KcpStack::new(
                socket,
                server_addr,
                conv,
                &mut tx,
                &mut rx,
                kcp_stack_rx,
                &interface.key,
            );

            if let Err(e) = stack.block_on().await {
                warn!("kcpstack err: {:?}", e);
            }
        });

        let (r, w) = tokio::io::split(handler_kcp_channel_from_tcp);
        (Box::new(r), Box::new(w))
    } else {
        let socket = if server_addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
    
        socket.set_nodelay(true)?;
    
        if let Some(device) = socket_bind_device {
            SocketExt::bind_device(&socket, device, server_addr.is_ipv6())?;
        }
    
        let stream = socket.connect(server_addr)
            .await
            .with_context(|| format!("connect to {} error", &group.server_addr))?;

        let (reader, writer) = stream.into_split();
        (Box::new(reader), Box::new(writer))
    };

    let mut buff = allocator::alloc(1024);

    let (virtual_addr, cidr) = match register_addr {
        RegisterVirtualAddr::Manual(addr) => *addr,
        RegisterVirtualAddr::Auto(Some(addr)) => *addr,
        RegisterVirtualAddr::Auto(None) => {
            let len = TcpMsg::get_idle_virtual_addr_encode(key, rand::random(), &mut buff);
            TcpMsg::write_msg(&mut writer, &buff[..len]).await?;

            let msg = TcpMsg::read_msg(&mut reader, key, &mut buff).await?
                .ok_or_else(|| anyhow!("server connection closed"))?;

            match msg {
                TcpMsg::GetIdleVirtualAddrRes(Some((addr, cidr))) => (addr, cidr),
                TcpMsg::GetIdleVirtualAddrRes(None) => return Err(anyhow!("insufficient address")),
                _ => return Err(anyhow!("invalid message")),
            }
        }
    };

    let now = Utc::now().timestamp();

    let reg = Register {
        node_name: group.node_name.clone(),
        virtual_addr,
        lan_udp_socket_addr,
        proto_mod: group.mode.clone(),
        register_time: now,
        nonce: random(),
        allowed_ips: group.allowed_ips.clone()
    };

    let len = TcpMsg::register_encode(key, rand::random(), &reg, &mut buff)?;
    TcpMsg::write_msg(&mut writer, &buff[..len]).await?;

    let ret = TcpMsg::read_msg(&mut reader, key, &mut buff).await?
        .ok_or_else(|| anyhow!("server connection closed"))?;

    let group_info = match ret {
        TcpMsg::RegisterRes(Err(RegisterError::InvalidVirtualAddress(e))) => {
            if e == AllocateError::IpAlreadyInUse {
                if let RegisterVirtualAddr::Auto(v) = register_addr {
                    *v = None;
                }
            }
            return Err(anyhow!(e))
        }
        TcpMsg::RegisterRes(res) => res?,
        _ => return Err(anyhow!("response message not match")),
    };

    if cidr != group_info.cidr {
        if let RegisterVirtualAddr::Auto(v) = register_addr {
            *v = None;
        }

        return Err(anyhow!("group cidr not match"));
    }

    if let RegisterVirtualAddr::Auto(None) = register_addr {
        *register_addr = RegisterVirtualAddr::Auto(Some((virtual_addr, cidr)));
        *refresh_route = true;
    }
    Ok(((reader, writer), group_info))
}

fn update_tun_addr<T, K, InterRT, ExternRt>(
    tun: &T,
    rt: &RoutingTableEnum<InterRT, ExternRt>,
    interface: &Interface<K>,
    allowed_ips: &[Ipv4Net],
    old_addr: VirtualAddr,
    addr: VirtualAddr,
    old_cidr: Ipv4Net,
    cidr: Ipv4Net,
) -> Result<()>
    where
        T: TunDevice,
        InterRT: RoutingTable + Clone,
        ExternRt: RoutingTable
{
    let item = Item {
        cidr,
        gateway: Ipv4Addr::UNSPECIFIED,
        interface_index: interface.index,
        extend: routing_table::Extend {
            item_kind: Some(ItemKind::VirtualRange)
        }
    };

    let allowed_ips_item = allowed_ips.iter()
        .map(|&allowed| Item {
            cidr: allowed,
            gateway: addr,
            interface_index: interface.index,
            extend: routing_table::Extend {
                item_kind: Some(ItemKind::AllowedIpsRoute)
            }
        })
        .collect::<Vec<_>>();

    let update_route = |t: &mut dyn RoutingTable| {
        // update default tun route
        if cidr != old_cidr {
            // todo add method for finding routing item
            if let Some(i) = t.remove(&old_cidr) {
                if i.extend.item_kind != Some(ItemKind::VirtualRange) {
                    t.add(i);
                }
            }

            t.add(item.clone());
        }

        // update allowed_ips route
        if addr != old_addr {
            for i in &allowed_ips_item {
                if let Some(old_item) = t.remove(&i.cidr) {
                    if old_item.extend.item_kind != Some(ItemKind::AllowedIpsRoute) {
                        t.add(old_item);
                    }
                }
               
                t.add(i.clone());
            }
        }
    };

    match rt {
        RoutingTableEnum::Internal(rt) => {
            rt.rcu(|v| {
                let mut t = (**v).clone();
                update_route(&mut t);
                t
            });
        }
        RoutingTableEnum::External(rt) => unsafe { update_route(&mut *rt.get()) }
    }

    if addr != old_addr ||
        cidr != old_cidr {
        tun.delete_addr(old_addr, old_cidr.netmask())?;
        tun.add_addr(addr, cidr.netmask())?;

        interface.addr.store(addr);
        interface.cidr.store(cidr);
    }
    Ok(())
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
fn update_hosts(hb: &hostsfile::HostsBuilder) -> std::io::Result<bool> {
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    let _guard = LOCK.lock();
    hb.write()
}

async fn tcp_handler<T, K, InterRT, ExternRt>(
    config: &'static NodeConfigFinalize<K>,
    group: &'static TargetGroupFinalize<K>,
    routing_table: Arc<RoutingTableEnum<InterRT, ExternRt>>,
    interface: Arc<Interface<K>>,
    tun: T,
    channel_rx: Option<Receiver<Bytes>>,
    sys_routing: Option<Arc<tokio::sync::Mutex<SystemRouteHandle>>>,
    routes: Vec<Route>,
    hooks: Option<Arc<Hooks<K>>>,
    #[cfg(feature = "cross-nat")]
    snat: Option<Arc<cross_nat::SNat>>,
    kcp_stack_rx: Option<Receiver<Bytes>>,
) -> Result<()>
where
    T: TunDevice + Clone + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
    InterRT: RoutingTable + Clone + Send + Sync + 'static,
    ExternRt: RoutingTable + Send + Sync + 'static
{
    let join: JoinHandle<Result<()>> = tokio::spawn(async move {
        let kcp_stack_rx = kcp_stack_rx.map(|v| Arc::new(tokio::sync::Mutex::new(v)));
        let mut sys_route_is_sync = false;

        // use defer must use atomic
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let is_add_nat = AtomicBool::new(false);

        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let host_records = Arc::new(parking_lot::Mutex::new(HashSet::new()));

        // todo requires Arc + Mutex to pass compile
        let channel_rx = channel_rx.map(|v| Arc::new(tokio::sync::Mutex::new(v)));

        #[cfg(all(
            feature = "cross-nat",
            any(target_os = "windows", target_os = "linux", target_os = "macos")
        ))]
        let native_nat = snat.is_none();

        #[cfg(all(
            not(feature = "cross-nat"),
            any(target_os = "windows", target_os = "linux", target_os = "macos")
        ))]
        let native_nat = true;

        defer! {
            debug!("exiting tcp handler function ...");

            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            if !config.features.disable_hosts_operation {
                let guard = host_records.lock();

                if !guard.is_empty() {
                    info!("clear node {} host records", group.node_name);

                    for host in &*guard {
                        let hb = hostsfile::HostsBuilder::new(host);

                        if let Err(e) = update_hosts(&hb) {
                            error!("failed to write hosts file: {}", e);
                        }
                    }
                }
            }

            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            if is_add_nat.load(Ordering::Relaxed) && native_nat {
                info!("clear node {} nat list", group.node_name);

                if let Err(e) = crate::nat::del_nat(&group.allowed_ips, interface.cidr.load()) {
                    error!("failed to delete nat: {}", e);
                }
            }

            debug!("tcp handler function exited");
        }

        let lan_udp_socket_addr = match (&interface.udp_socket, &group.lan_ip_addr) {
            (Some(s), Some(lan_ip)) => Some(SocketAddr::new(*lan_ip, s.local_addr()?.port())),
            _ => None,
        };

        let mut tun_addr = match &group.tun_addr {
            None => RegisterVirtualAddr::Auto(None),
            Some(addr) => {
                let cidr = Ipv4Net::with_netmask(addr.ip, addr.netmask)?.trunc();

                update_tun_addr(
                    &tun,
                    &routing_table,
                    &*interface,
                    &group.allowed_ips,
                    VirtualAddr::UNSPECIFIED,
                    addr.ip,
                    Ipv4Net::default(),
                    cidr,
                )?;

                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                if !group.allowed_ips.is_empty() && native_nat {
                    crate::nat::add_nat(&group.allowed_ips, cidr)?;
                    is_add_nat.store(true, Ordering::Relaxed);
                }

                RegisterVirtualAddr::Manual((addr.ip, cidr))
            }
        };

        let key = &group.key;

        loop {
            let mut non_retryable = false;

            let process = async {
                let mut refresh_route= false;

                let ((rx, mut tx), group_info) = tokio::time::timeout(
                    Duration::from_secs(10),
                    register(
                        group,
                        interface.clone(),
                        key,
                        &mut tun_addr,
                        lan_udp_socket_addr,
                        &mut refresh_route,
                        config.socket_bind_device.as_deref(),
                        kcp_stack_rx.clone(),
                    )
                ).await.with_context(|| format!("register to {} timeout", group.server_addr))??;

                if refresh_route {
                    if let RegisterVirtualAddr::Auto(Some((addr, cidr))) = &tun_addr {
                        let old_addr = interface.addr.load();
                        let old_cidr = interface.cidr.load();

                        let f = || {
                            update_tun_addr(
                                &tun,
                                &routing_table,
                                &*interface,
                                &group.allowed_ips,
                                old_addr,
                                *addr,
                                old_cidr,
                                *cidr,
                            )?;

                            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                            if !group.allowed_ips.is_empty() && native_nat {
                                if old_cidr != *cidr &&
                                    is_add_nat.load(Ordering::Relaxed)
                                {
                                    crate::nat::del_nat(&group.allowed_ips,old_cidr)?;
                                    is_add_nat.store(false, Ordering::Relaxed);
                                }

                                if !is_add_nat.load(Ordering::Relaxed) {
                                    crate::nat::add_nat(&group.allowed_ips, *cidr)?;
                                    is_add_nat.store(true, Ordering::Relaxed);
                                }
                            }
                            Result::<_, Error>::Ok(())
                        };

                        if let Err(e) = f() {
                            non_retryable = true;
                            error!("refresh route failed: {}", e);
                            return Err(e);
                        }
                    }
                }

                interface.group_name.store(Some(Arc::new(group_info.name.clone())));
                interface.server_allow_udp_relay.store(group_info.allow_udp_relay, Ordering::Relaxed);
                interface.server_allow_tcp_relay.store(group_info.allow_tcp_relay, Ordering::Relaxed);

                // tun must first set the ip address
                if !sys_route_is_sync {
                    let res = match &sys_routing {
                        None => Ok(()),
                        Some(routing) => routing.lock().await.add(&routes).await
                    };

                    if let Err(e) = res {
                        non_retryable = true;
                        error!("failed to add route: {}", e);
                        return Err(e);
                    }

                    sys_route_is_sync = true;
                }

                interface.server_is_connected.store(true, Ordering::Relaxed);
                info!("node {}({}) has joined group {}", group.node_name, interface.addr.load(), group_info.name);
                info!("group {} address range {}", group_info.name, group_info.cidr);

                let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

                let (inner_channel_tx, mut inner_channel_rx) = unbounded_channel::<Bytes>();
                let (_notify, notified) = tokio::sync::watch::channel(());

                let recv_handler = async {
                    let mut notified = notified.clone();
                    let interface = interface.clone();
                    let inner_channel_tx = inner_channel_tx.clone();

                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let host_records = host_records.clone();

                    let tun = tun.clone();
                    let routing_table = routing_table.clone();
                    let hooks = hooks.clone();
                    #[cfg(feature = "cross-nat")]
                    let snat = snat.clone();

                    let join = tokio::spawn(async move {
                        let fut = async {
                            let arr = [interface.as_ref()];
                            let mut sender = PacketSender::new(
                                &*routing_table, 
                                &arr, 
                                &tun, 
                                hooks.as_deref(), 
                                #[cfg(feature = "cross-nat")]
                                snat.as_deref()
                            );

                            let mut rng = rand::rngs::SmallRng::from_os_rng();

                            const START: usize = UDP_MSG_HEADER_LEN;
                            let mut buff = vec![0u8; TCP_BUFF_SIZE];

                            loop {
                                let msg = TcpMsg::read_msg(&mut rx, key, &mut buff[START..]).await?
                                    .ok_or_else(|| anyhow!("server connection closed"))?;

                                match msg {
                                    TcpMsg::NodeMap(map) => {
                                        let mut new_list = NodeList::with_capacity(map.len());

                                        {
                                            let old_list = interface.node_list.load();

                                            for (virtual_addr, node) in map {
                                                match old_list.get_node(&virtual_addr) {
                                                    None => {
                                                        new_list.push(ExtendedNode::from(node));
                                                    },
                                                    Some(v) => {
                                                        let en = ExtendedNode {
                                                            node,
                                                            hc: v.hc.clone(),
                                                            udp_status: v.udp_status.clone(),
                                                            peer_addr: v.peer_addr.clone()
                                                        };
                                                        new_list.push(en);
                                                    }
                                                }
                                            }
                                        }

                                        new_list.sort_unstable_by_key(|n| n.node.virtual_addr);

                                        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                                        if !config.features.disable_hosts_operation {
                                            let host_key = format!("FUBUKI-{}", group_info.name);
                                            let mut hb = hostsfile::HostsBuilder::new(&host_key);
                                            host_records.lock().insert(host_key);

                                            for node in &new_list {
                                                let node = &node.node;
                                                hb.add_hostname(IpAddr::from(node.virtual_addr), format!("{}.{}", &node.name, &group_info.name));
                                            }

                                            tokio::task::spawn_blocking(move || {
                                                let node_name = &group.node_name;

                                                match update_hosts(&hb) {
                                                    Ok(true) => info!("node {} update hosts", node_name),
                                                    Ok(false) => (),
                                                    Err(e) => error!("node {} update hosts error: {}", node_name, e)
                                                }
                                            });
                                        }

                                        interface.node_list.store(Arc::new(new_list));
                                    }
                                    TcpMsg::Relay(dst, data) => {
                                        const DATA_START: usize = START + size_of::<VirtualAddr>();
                                        sender.send_packet(
                                            Direction::Input,
                                            DATA_START..DATA_START + data.len(),
                                            &mut buff,
                                            config.allow_packet_forward,
                                            config.allow_packet_not_in_rules_send_to_kernel,
                                            Some(dst)
                                        ).await?;
                                    }
                                    TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                                        let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                                        TcpMsg::heartbeat_encode(key, rng.random(), seq, HeartbeatType::Resp, &mut buff);

                                        let res = inner_channel_tx
                                            .send(buff)
                                            .map_err(|e| anyhow!(e));

                                        if res.is_err() {
                                            return res;
                                        }
                                    }
                                    TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                                        interface.server_tcp_hc.write().reply(recv_seq);
                                    }
                                    TcpMsg::FetchPeersRes(peers) => {
                                        if let Some(peers_map) = &interface.peers_map {
                                            *peers_map.write() = peers;
                                        }
                                    }
                                    _ => continue,
                                }
                            }
                        };

                        tokio::select! {
                            res = fut => res,
                            _ = notified.changed() => Err(anyhow!("abort task"))
                        }
                    });

                    join.await?
                };

                let send_handler = async {
                    let mut notified = notified.clone();
                    let channel_rx = channel_rx.clone();
                    let interface = interface.clone();

                    let join = tokio::spawn(async move {
                        let mut channel_rx = match &channel_rx {
                            None => None,
                            Some(lock) => Some(lock.lock().await)
                        };

                        let mut interval = if interface.peers_map.is_some() {
                            Some(tokio::time::interval(Duration::from_secs(30)))
                        } else {
                            None
                        };

                        loop {
                            tokio::select! {
                                opt = inner_channel_rx.recv() => {
                                    match opt {
                                        Some(buff) => TcpMsg::write_msg(&mut tx, &buff).await?,
                                        None => return Ok(())
                                    };
                                }
                                opt = match channel_rx {
                                    Some(ref mut v) => v.recv().right_future(),
                                    None => std::future::pending().left_future()
                                } => {
                                    match opt {
                                        Some(buff) => TcpMsg::write_msg(&mut tx, &buff).await?,
                                        None => return Ok(())
                                    };
                                }
                                _ = match interval {
                                    Some(ref mut interval) => interval.tick().right_future(),
                                    None => std::future::pending().left_future()
                                } => {
                                    let mut buff = [0u8; TCP_MSG_HEADER_LEN];
                                    TcpMsg::fetch_peers_encode(key, rand::random(), &mut buff);
                                    TcpMsg::write_msg(&mut tx, &buff).await?;
                                }
                                _ = notified.changed() => return Err(anyhow!("abort task"))
                            }
                        }
                    });

                    join.await?
                };

                let heartbeat_schedule = async {
                    let mut notified = notified.clone();
                    let interface = interface.clone();
                    let inner_channel_tx = inner_channel_tx.clone();

                    let join = tokio::spawn(async move {
                        let fut = async {
                            let mut rng = rand::rngs::SmallRng::from_os_rng();
                            
                            loop {
                                let seq = {
                                    let mut guard = interface.server_tcp_hc.write();
                                    guard.check();

                                    if guard.packet_continuous_loss_count >= config.tcp_heartbeat_continuous_loss {
                                        return Result::<(), _>::Err(anyhow!("receive tcp heartbeat timeout"));
                                    }

                                    guard.ping();
                                    guard.seq
                                };

                                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                                TcpMsg::heartbeat_encode(key, rng.random(), seq, HeartbeatType::Req, &mut buff);
                                inner_channel_tx.send(buff).map_err(|e| anyhow!(e))?;

                                tokio::time::sleep(config.tcp_heartbeat_interval).await;
                            }
                        };

                        tokio::select! {
                            res = fut => res,
                            _ = notified.changed() => Err(anyhow!("abort task"))
                        }
                    });

                    join.await?
                };

                let update_peers_schedule = async {
                    let mut notified = notified.clone();
                    let interface = interface.clone();
                    let inner_channel_tx = inner_channel_tx.clone();

                    let join: JoinHandle<Result<()>> = tokio::spawn(async move {
                        let fut = async {
                            let mut rng = rand::rngs::SmallRng::from_os_rng();
                            let node_list = &interface.node_list;
                            let specify_mode = &interface.specify_mode;
                            let mut buff = vec![0u8; TCP_BUFF_SIZE];

                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;

                                let peers_status = {
                                    let node_list = node_list.load_full();
                                    let mut peers_status = Vec::with_capacity(node_list.len());

                                    for node in  &*node_list {
                                        let p2p_available = node.udp_status.load() != UdpStatus::Unavailable &&
                                        specify_mode
                                            .get(&node.node.virtual_addr)
                                            .map(|mode| !mode.p2p.is_empty())
                                            .unwrap_or(true);

                                        let (latency, packet_loss) = if p2p_available {
                                            let guard = node.hc.read();
                                            let latency = guard.last_elapsed;
                                            let loss_rate = guard.packet_loss_count * 100 / guard.send_count;

                                            (latency, Some(loss_rate as u8))
                                        } else {
                                            (None, None)
                                        };

                                        let peer = PeerStatus {
                                            addr: node.node.virtual_addr,
                                            latency,
                                            packet_loss
                                        };

                                        peers_status.push(peer);
                                    }

                                    peers_status
                                };

                                let len = TcpMsg::upload_peers_encode(key, rng.random(), &peers_status, &mut buff)?;
                                let mut packet = allocator::alloc(len);
                                packet.copy_from_slice(&buff[..len]);
                                inner_channel_tx.send(packet).map_err(|e| anyhow!(e))?;
                            }
                        };

                        tokio::select! {
                            res = fut => res,
                            _ = notified.changed() => Err(anyhow!("abort task"))
                        }
                    });

                    join.await?
                };

                let update_peers_schedule = if config.allow_packet_forward && !group.mode.p2p.is_empty() {
                    update_peers_schedule.left_future()
                } else {
                    std::future::pending().right_future()
                };

                tokio::try_join!(
                    recv_handler, 
                    send_handler, 
                    heartbeat_schedule, 
                    update_peers_schedule
                )?;
                Result::<_, Error>::Ok(())
            };

            if let Err(e) = process.await {
                if non_retryable {
                    error!("node {} got non-retryable error: {}", group.node_name, e);
                    return Err(e)
                }
                error!("node {} tcp handler error: {:?}", &group.node_name, e)
            }

            interface.server_is_connected.store(false, Ordering::Relaxed);

            {
                let mut guard = interface.server_tcp_hc.write();
                guard.packet_continuous_loss_count = 0;
                guard.is_send = false;
            }

            time::sleep(config.reconnect_interval).await;
        }
    });

    join.await?.with_context(|| format!("node {} tcp handler error", group.node_name))
}

pub extern "C" fn generic_interfaces_info<K>(
    interfaces: &OnceLock<Vec<Arc<Interface<K>>>>,
    info_json: *mut c_char
) {
    let empty_interfaces = Vec::new();
    let interfaces = interfaces.get().unwrap_or(&empty_interfaces);
    let mut list = Vec::with_capacity(interfaces.len());

    for inter in interfaces {
        list.push(InterfaceInfo::from(&**inter));
    }

    let out = CString::new(serde_json::to_string(&list).unwrap()).unwrap();
    let out = out.as_bytes_with_nul();
    unsafe { std::ptr::copy(out.as_ptr(), info_json as *mut u8, out.len()) };
}

pub extern "C" fn interfaces_info_query<K>(ctx: &Context<K>, info_json: *mut c_char) {
    if let Some(ifs) = ctx.interfaces.as_deref() {
        generic_interfaces_info(ifs, info_json)
    }
}

pub extern "C" fn packet_send<K>(
    ctx: &Context<K>,
    direction: Direction,
    packet: *const u8,
    len: usize
) {
    if let Some(tx) = ctx.send_packet_chan.as_ref() {
        let packet = unsafe { slice::from_raw_parts(packet, len) };
        let mut buff = allocator::alloc(packet.len());
        buff.copy_from_slice(packet);
    
        let _ = tx.try_send((direction, buff));
    }
}

async fn send_packet_hook_handler<T, K, InterRT, ExternRT>(
    config: &'static NodeConfigFinalize<K>,
    send_packet_chan_rx: flume::Receiver<(Direction, Bytes)>,
    tun: T,
    routing_table: Arc<RoutingTableEnum<InterRT, ExternRT>>,
    interfaces: Vec<Arc<Interface<K>>>,
    hooks: Option<Arc<Hooks<K>>>,
    #[cfg(feature = "cross-nat")]
    snat: Option<Arc<cross_nat::SNat>>
) -> Result<()>
    where
        T: TunDevice + Clone + Send + Sync + 'static,
        K: Cipher + Clone + Send + Sync + 'static,
        InterRT: RoutingTable + Send + Sync + 'static,
        ExternRT: RoutingTable + Send + Sync + 'static
{
    let join: JoinHandle<Result<()>> = tokio::spawn(async move {
        let interfaces = interfaces.iter().map(|v| &**v).collect::<Vec<_>>();

        let mut sender = PacketSender::new(
            &*routing_table,
            &interfaces,
            &tun,
            hooks.as_deref(),
            #[cfg(feature = "cross-nat")]
            snat.as_deref()
        );

        let mut buff = vec![0u8; UDP_BUFF_SIZE];

        loop {
            const START: usize = UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>();
            let (direction, packet) = send_packet_chan_rx.recv_async().await?;

            if packet.len() == 0 {
                continue;
            }

            let packet_range = START..START + packet.len();
            buff[packet_range.clone()].copy_from_slice(&packet);

            match direction {
                Direction::Input => {
                    sender.send_packet(
                        Direction::Input,
                        packet_range,
                        &mut buff,
                        config.allow_packet_forward,
                        config.allow_packet_not_in_rules_send_to_kernel,
                        None,
                    ).await?;
                }
                Direction::Output => {
                    sender.send_packet(
                        Direction::Output,
                        packet_range,
                        &mut buff,
                        true,
                        false,
                        None,
                    ).await?;
                }
            }
        }
    });
    join.await?
}

pub async fn start<K, T>(
    config: NodeConfigFinalize<K>, 
    tun: T,
    interfaces_hook: Arc<OnceLock<Vec<Arc<Interface<K>>>>>
) -> Result<()>
    where
        K: Cipher + Send + Sync + Clone + 'static,
        T: TunDevice + Send + Sync + 'static,
{
    let config = &*Box::leak(Box::new(config));
    let tun = Arc::new(tun);
    tun.set_mtu(config.mtu)?;

    let (send_packet_chan_tx, send_packet_chan_rx) = flume::bounded(1024);

    let ctx = Context {
        interfaces: Some(interfaces_hook.clone()),
        send_packet_chan: Some(send_packet_chan_tx)
    };

    let curr = std::env::current_exe().ok();
    let parent = curr.as_deref().and_then(|v| v.parent()).unwrap_or(Path::new(""));

    let ctx = Arc::new(ctx);

    let hooks = if config.enable_hook {
        let dll_name = format!("{}fubukihook{}", env::consts::DLL_PREFIX, env::consts::DLL_SUFFIX);
        let hooks = common::hook::open_hooks_dll(&parent.join(Path::new(&dll_name)), ctx.clone())?;
        Some(Arc::new(hooks))
    } else {
        None
    };

    let init_routing_table = |rt: &mut dyn RoutingTable| {
        for (index, group) in config.groups.iter().enumerate() {
            for (dst, cidrs) in &group.ips {
                for cidr in cidrs {
                    let item = Item {
                        cidr: *cidr,
                        gateway: *dst,
                        interface_index: index,
                        extend: routing_table::Extend {
                            item_kind: Some(ItemKind::IpsRoute)
                        }
                    };

                    rt.add(item);
                }
            }
        }
    };

    let rt = if config.external_routing_table {
        let dll_name = format!("{}fubukiextrt{}", env::consts::DLL_PREFIX, env::consts::DLL_SUFFIX);
    
        let mut rt = routing_table::external::create::<K>(
            &parent.join(Path::new(&dll_name)),
            ctx.clone()
        )?;
        init_routing_table(&mut rt);
        RoutingTableEnum::External(SyncUnsafeCell::new(rt))
    } else {
        let mut rt = routing_table::internal::create();
        init_routing_table(&mut rt);
        RoutingTableEnum::Internal(ArcSwap::from_pointee(rt))
    };

    let rt = Arc::new(rt);

    #[cfg(feature = "cross-nat")]
    let allowed_ips_exists = {
        let mut ret = false;

        for group in config.groups.iter() {
            if !group.allowed_ips.is_empty() {
                ret = true;
                break;
            }
        }
        ret
    };

    #[cfg(feature = "cross-nat")]
    let snat = if config.cross_nat && allowed_ips_exists {
        let snat = cross_nat::SNat::create(
            rt.clone(), 
            interfaces_hook.clone(), 
            tun.clone(), 
            hooks.clone(), 
        )?;
        Some(Arc::new(snat))
    } else {
        None
    };

    let mut future_list: Vec<BoxFuture<Result<()>>> = Vec::new();
    let mut interfaces = Vec::with_capacity(config.groups.len());
    let sys_routing = if config.features.disable_route_operation { None } else {
        let arc = Arc::new(tokio::sync::Mutex::new(SystemRouteHandle::new()?));
        Some(arc)
    };
    #[allow(unused)]
    let tun_index = tun.get_index();

    for (index, group) in config.groups.iter().enumerate() {
        let (channel_tx, channel_rx) = if group.mode.is_use_tcp() {
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(config.channel_limit);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let udp_opt = match group.lan_ip_addr {
            Some(lan_ip_addr) if group.mode.is_use_udp() || group.use_kcp_session => {
                let bind_addr = if let Some(node_bind) = group.node_binding {
                    node_bind
                } else {
                    let bind_addr = match lan_ip_addr {
                        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                    };
                    SocketAddr::new(bind_addr, 0)
                };

                let udp_socket = UdpSocket::bind(bind_addr)
                    .await
                    .context("create udp socket failed")?;

                if let Some(v) = config.udp_socket_recv_buffer_size {
                    udp_socket.set_recv_buffer_size(v)?;
                }

                if let Some(v) = config.udp_socket_send_buffer_size {
                    udp_socket.set_send_buffer_size(v)?;
                }

                if let Some(device) = &config.socket_bind_device {
                    SocketExt::bind_device(&udp_socket, device, bind_addr.is_ipv6())?;
                }
                Some(udp_socket)
            }
            _ => None,
        };

        let interface = Interface {
            index,
            node_name: group.node_name.clone(),
            group_name: ArcSwapOption::empty(),
            addr: AtomicAddr::from(VirtualAddr::UNSPECIFIED),
            cidr: AtomicCidr::from(Ipv4Net::default()),
            mode: group.mode.clone(),
            specify_mode: group.specify_mode.iter().map(|(k, v)| (*k, v.clone())).collect(),
            node_list: ArcSwap::from_pointee(NodeList::new()),
            server_addr: group.server_addr.clone(),
            server_udp_hc: RwLock::new(HeartbeatCache::new()),
            server_udp_status: AtomicCell::new(UdpStatus::Unavailable),
            server_tcp_hc: RwLock::new(HeartbeatCache::new()),
            server_is_connected: AtomicBool::new(false),
            server_allow_udp_relay: AtomicBool::new(false),
            server_allow_tcp_relay: AtomicBool::new(false),
            tcp_handler_channel: channel_tx,
            udp_socket: udp_opt,
            key: group.key.clone(),
            peers_map: {
                if group.auto_route_selection {
                    Some(RwLock::new(HashMap::new()))
                } else {
                    None
                }
            }
        };

        let interface = Arc::new(interface);
        interfaces.push(interface.clone());

        #[allow(unused_mut)]
        let mut routes = Vec::new();

        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        for (gateway, cidrs) in &group.ips {
            for cidr in cidrs {
                let route = Route::new(IpAddr::V4(cidr.network()), cidr.prefix_len())
                    .with_gateway(IpAddr::V4(*gateway))
                    .with_ifindex(tun_index);

                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let route = route.with_metric(1);

                routes.push(route);
            }
        }

        let (kcpstack_tx, kcpstack_rx) = if group.use_kcp_session {
            Some(tokio::sync::mpsc::channel(1024)).unzip()
        } else {
            None.unzip()
        };

        let fut = tcp_handler(
            config,
            group,
            rt.clone(),
            interface.clone(),
            tun.clone(),
            channel_rx,
            sys_routing.clone(),
            routes,
            hooks.clone(),
            #[cfg(feature = "cross-nat")]
            snat.clone(),
            kcpstack_rx,
        );
        future_list.push(Box::pin(fut));

        if interface.udp_socket.is_some() {
            let fut = udp_handler(
                config,
                group,
                rt.clone(),
                interface,
                tun.clone(),
                hooks.clone(),
                #[cfg(feature = "cross-nat")]
                snat.clone(),
                kcpstack_tx,
            );
            future_list.push(Box::pin(fut));
        }
    };

    let _ = interfaces_hook.set(interfaces.clone());
   
    let tun_handler_fut = tun_handler(
        tun.clone(), 
        rt.clone(),
         interfaces.clone(), 
         hooks, 
         #[cfg(feature = "cross-nat")]
         snat.clone()
    );
    future_list.push(Box::pin(tun_handler_fut));
    if !config.features.disable_api_server {
        future_list.push(Box::pin(api_start(config.api_addr, interfaces.clone())));
    }

    if Arc::strong_count(&ctx) > 1 {
        future_list.push(Box::pin(send_packet_hook_handler(
            config, 
            send_packet_chan_rx, 
            tun, 
            rt, 
            interfaces, 
            None,
            #[cfg(feature = "cross-nat")]
            snat
        )));
    } else {
        drop(ctx);
        drop(send_packet_chan_rx);
    }

    let serve = futures_util::future::try_join_all(future_list);

    if config.features.disable_signal_handling {
        serve.await?;
    } else {

        #[cfg(windows)]
        {
            let mut ctrl_c = signal::windows::ctrl_c()?;
            let mut ctrl_close = signal::windows::ctrl_close()?;

            tokio::select! {
                _ = ctrl_c.recv() => (),
                _ = ctrl_close.recv() => (),
                res = serve => {
                    res?;
                },
            };
        }

        #[cfg(unix)]
        {
            let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
            let mut interrupt = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

            tokio::select! {
                _ = terminate.recv() => (),
                _ = interrupt.recv() => (),
                res = serve => {
                    res?;
                },
            };
        }

    }

    Ok(())
}

pub async fn info(api_addr: &str) -> Result<()> {
    let mut info_app = info_tui::App::new(api_addr.to_string());
    info_app.run().await?;
    Ok(())
}
