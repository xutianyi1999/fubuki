use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use anyhow::{anyhow, Context as AnyhowContext};
use anyhow::Result;
use arc_swap::{ArcSwap, ArcSwapOption, Cache};
use chrono::Utc;
use futures_util::future::LocalBoxFuture;
use futures_util::FutureExt;
use hyper::{Body, Method, Request};
use hyper::body::Buf;
use ipnet::Ipv4Net;
use net_route::Route;
use parking_lot::{Mutex, RwLock};
use prettytable::{row, Table};
use rand::random;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::mpsc::{Receiver, Sender, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time;

use crate::{Cipher, NodeConfigFinalize, NodeInfoType, ProtocolMode, TargetGroupFinalize, tun};
use crate::common::{allocator, utc_to_str};
use crate::common::allocator::Bytes;
use crate::common::net::{get_ip_dst_addr, get_ip_src_addr, HeartbeatCache, HeartbeatInfo, SocketExt, UdpStatus};
use crate::common::net::protocol::{AllocateError, GroupContent, HeartbeatType, NetProtocol, Node, Register, RegisterError, Seq, SERVER_VIRTUAL_ADDR, TCP_BUFF_SIZE, TCP_MSG_HEADER_LEN, TcpMsg, UDP_BUFF_SIZE, UDP_MSP_HEADER_LEN, UdpMsg, VirtualAddr};
use crate::common::routing_table::RoutingTable;
use crate::node::api::api_start;
use crate::nat::{add_nat, del_nat};
use crate::node::sys_route::SystemRouteHandle;
use crate::tun::TunDevice;

mod api;
mod sys_route;

type NodeMap = HashMap<VirtualAddr, ExtendedNode>;

struct AtomicAddr {
    inner: AtomicU32
}

impl AtomicAddr {
    fn load(&self) -> Ipv4Addr {
        VirtualAddr::from(self.inner.load(Ordering::Relaxed))
    }

    fn store(&self, addr: VirtualAddr) {
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

struct Interface<K> {
    index: usize,
    node_name: String,
    group_name: ArcSwapOption<String>,
    addr: AtomicAddr,
    cidr: AtomicCidr,
    mode: ProtocolMode,
    node_map: ArcSwap<NodeMap>,
    server_addr: String,
    server_udp_hc: RwLock<HeartbeatCache>,
    server_udp_status: ArcSwap<UdpStatus>,
    server_tcp_hc: RwLock<HeartbeatCache>,
    server_is_connected: AtomicBool,
    tcp_handler_channel: Option<Sender<Bytes>>,
    udp_socket: Option<UdpSocket>,
    key: K,
}

#[derive(Serialize, Deserialize, Clone)]
struct InterfaceInfo {
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
                value.node_map
                    .load_full()
                    .iter()
                    .map(|(k, v)| {
                        (*k, ExtendedNodeInfo::from(v))
                    })
                    .collect()
            },
            server_addr: value.server_addr.clone(),
            server_udp_hc: HeartbeatInfo::from(&*value.server_udp_hc.read()),
            server_udp_status: (**value.server_udp_status.load()),
            server_tcp_hc: HeartbeatInfo::from(&*value.server_tcp_hc.read()),
            server_is_connected: value.server_is_connected.load(Ordering::Relaxed)
        }
    }
}

#[allow(unused)]
struct InterfaceCache<'a, K> {
    addr: &'a AtomicAddr,
    cidr: &'a AtomicCidr,
    mode: &'a ProtocolMode,
    node_map: Cache<&'a ArcSwap<NodeMap>, Arc<NodeMap>>,
    server_addr: &'a str,
    server_udp_hc: &'a RwLock<HeartbeatCache>,
    server_udp_status: Cache<&'a ArcSwap<UdpStatus>, Arc<UdpStatus>>,
    server_tcp_hc: &'a RwLock<HeartbeatCache>,
    server_is_connected: &'a AtomicBool,
    tcp_handler_channel: Option<&'a Sender<Bytes>>,
    udp_socket: Option<&'a UdpSocket>,
    key: &'a K,
}

impl <'a, K> From<&'a Interface<K>> for InterfaceCache<'a, K> {
    fn from(value: &'a Interface<K>) -> Self {
        InterfaceCache {
            addr: &value.addr,
            cidr: &value.cidr,
            mode: &value.mode,
            node_map: Cache::new(&value.node_map),
            server_addr: &value.server_addr,
            server_udp_hc: &value.server_udp_hc,
            server_udp_status: Cache::new(&value.server_udp_status),
            server_tcp_hc: &value.server_tcp_hc,
            server_is_connected: &value.server_is_connected,
            tcp_handler_channel: value.tcp_handler_channel.as_ref(),
            udp_socket: value.udp_socket.as_ref(),
            key: &value.key
        }
    }
}

struct ExtendedNode {
    pub node: Node,
    pub udp_status: Arc<ArcSwap<UdpStatus>>,
    pub hc: Arc<RwLock<HeartbeatCache>>,
    pub peer_addr: Arc<ArcSwapOption<SocketAddr>>
}

impl From<Node> for ExtendedNode {
    fn from(node: Node) -> Self {
        ExtendedNode {
            node,
            udp_status: Arc::new(ArcSwap::from_pointee(UdpStatus::Unavailable)),
            hc: Arc::new(RwLock::new(HeartbeatCache::new())),
            peer_addr: Arc::new(ArcSwapOption::empty())
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
            udp_status: **value.udp_status.load(),
            hc: HeartbeatInfo::from(&*value.hc.read())
        }
    }
}

async fn lookup_host(dst: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(dst).await.ok()?.next()
}

async fn send<K: Cipher>(
    inter: &Interface<K>,
    dst_node: &ExtendedNode,
    server_udp_status: &UdpStatus,
    buff: &mut [u8],
    packet_range: Range<usize>
) -> Result<()> {
    if (!inter.mode.p2p.is_empty()) && (!dst_node.node.mode.p2p.is_empty()) {
        let udp_status = **dst_node.udp_status.load();

        if let UdpStatus::Available { dst_addr } = udp_status {
            debug!("tun handler: udp message p2p to node {}", dst_node.node.name);

            let socket = match &inter.udp_socket {
                None => unreachable!(),
                Some(socket) => socket,
            };

            let packet = &mut buff[packet_range.start - UDP_MSP_HEADER_LEN..packet_range.end];
            UdpMsg::data_encode(packet_range.len(), packet);
            inter.key.encrypt(packet, 0);
            socket.send_to(packet, dst_addr).await?;
            return Ok(());
        }
    }

    if (!inter.mode.relay.is_empty()) && (!dst_node.node.mode.relay.is_empty()) {
        for np in &inter.mode.relay {
            match np {
                NetProtocol::TCP => {
                    let tx = match inter.tcp_handler_channel {
                        None => unreachable!(),
                        Some(ref v) => v,
                    };

                    const DATA_START: usize = TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>();
                    let mut packet = allocator::alloc(DATA_START + packet_range.len());
                    packet[DATA_START..].copy_from_slice(&buff[packet_range.start..packet_range.end]);

                    TcpMsg::relay_encode(dst_node.node.virtual_addr, packet_range.len(), &mut packet);
                    inter.key.encrypt(&mut packet, 0);

                    match tx.try_send(packet) {
                        Ok(_) => {
                            debug!("tun handler: tcp message relay to node {}", dst_node.node.name);
                            return Ok(());
                        },
                        Err(e) => error!("tun handler: tunnel error: {}", e)
                    }
                }
                NetProtocol::UDP => {
                    let socket = match &inter.udp_socket {
                        None => unreachable!(),
                        Some(socket) => socket,
                    };

                    let dst_addr = match *server_udp_status {
                        UdpStatus::Available { dst_addr } => dst_addr,
                        UdpStatus::Unavailable => continue,
                    };

                    debug!("tun handler: udp message relay to node {}", dst_node.node.name);

                    let packet = &mut buff[packet_range.start - size_of::<VirtualAddr>() - UDP_MSP_HEADER_LEN..packet_range.end];

                    UdpMsg::relay_encode(dst_node.node.virtual_addr, packet_range.len(), packet);
                    inter.key.encrypt(packet, 0);
                    socket.send_to(packet, dst_addr).await?;
                    return Ok(())
                }
            };
        }
    }

    warn!("no route to {}", dst_node.node.name);
    Ok(())
}

enum TransferType {
    Unicast(VirtualAddr),
    Broadcast,
}

async fn tun_handler<T, K>(
    tun: T,
    routing_table: Arc<ArcSwap<RoutingTable>>,
    interfaces: Vec<Arc<Interface<K>>>,
) -> Result<()>
where
    T: TunDevice + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
{
    let join: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut rh_cache = Cache::new(&*routing_table);

        let mut interfaces_cache: Vec<InterfaceCache<K>> = interfaces.iter()
            .map(|v| InterfaceCache::from(&**v))
            .collect();

        let mut buff = vec![0u8; UDP_BUFF_SIZE];

        loop {
            const START: usize = UDP_MSP_HEADER_LEN + size_of::<VirtualAddr>();

            let data = match tun
                .recv_packet(&mut buff[START..])
                .await
                .context("error receive packet from tun")?
            {
                0 => continue,
                len => &buff[START..START + len],
            };

            let packet_range = START..START + data.len();
            let src_addr = get_ip_src_addr(data)?;
            let dst_addr = get_ip_dst_addr(data)?;

            let rt = &**rh_cache.load();
            let item = match rt.find(dst_addr) {
                None => continue,
                Some(item) => item,
            };

            let interface_cache = &mut interfaces_cache[item.interface_index];
            let interface_addr = interface_cache.addr.load();
            let interface_cidr = interface_cache.cidr.load();

            if !interface_cache.server_is_connected.load(Ordering::Relaxed) {
                continue;
            }

            let transfer_type = if interface_addr == item.gateway {
                if dst_addr.is_broadcast() && interface_addr == src_addr {
                    TransferType::Broadcast
                } else if interface_cidr.broadcast() == dst_addr {
                    TransferType::Broadcast
                } else {
                    TransferType::Unicast(dst_addr)
                }
            } else {
                TransferType::Unicast(item.gateway)
            };

            let server_us = &**interface_cache.server_udp_status.load();
            let node_map = &**interface_cache.node_map.load();

            let inter = &*interfaces[item.interface_index];

            match transfer_type {
                TransferType::Unicast(addr) => {
                    debug!("tun handler: packet {}->{}; gateway: {}", src_addr, dst_addr, item.gateway);

                    if interface_addr == addr {
                        tun.send_packet(data).await.context("error send packet to tun")?;
                        continue;
                    }

                    let node = match node_map.get(&addr) {
                        None => {
                            warn!("cannot find node {}", addr);
                            continue;
                        },
                        Some(node) => node
                    };

                    send(inter, node, server_us, &mut buff, packet_range).await?
                }
                TransferType::Broadcast => {
                    debug!("tun handler: packet {}->{}; broadcast", src_addr, dst_addr);

                    for node in node_map.values() {
                        if node.node.virtual_addr == interface_addr {
                            continue;
                        }

                        send(inter, node, server_us, &mut buff, packet_range.clone()).await?;
                    }
                }
            }
        }
    });
    join.await?.context("tun handler error")
}

fn in_routing_table(routing_table: &RoutingTable, dst: SocketAddr) -> bool {
    match dst {
        SocketAddr::V4(addr) => {
           routing_table.find(*addr.ip()).is_some()
        }
        SocketAddr::V6(_) => false
    }
}

async fn udp_handler<T, K>(
    config: &'static NodeConfigFinalize<K>,
    group: &'static TargetGroupFinalize<K>,
    table: Arc<ArcSwap<RoutingTable>>,
    interface: Arc<Interface<K>>,
    tun: T,
) -> Result<()>
where
    T: TunDevice + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
{
    let join = tokio::spawn(async move {
        let socket = interface.udp_socket.as_ref().expect("must need udp socket");
        let key = &interface.key;
        let is_p2p = interface.mode.p2p.contains(&NetProtocol::UDP);

        let heartbeat_schedule =  async {
            let mut packet = vec![0u8; UDP_MSP_HEADER_LEN + size_of::<VirtualAddr>() + size_of::<Seq>() + size_of::<HeartbeatType>()];

            loop {
                let interface_addr = interface.addr.load();

                if interface.server_is_connected.load(Ordering::Relaxed) {
                    let server_hc = &interface.server_udp_hc;
                    let seq = {
                        let mut server_hc_guard = server_hc.write();
                        server_hc_guard.check();

                        if server_hc_guard.packet_continuous_loss_count >= config.udp_heartbeat_continuous_loss &&
                            **interface.server_udp_status.load() != UdpStatus::Unavailable
                        {
                            interface.server_udp_status.store(Arc::new(UdpStatus::Unavailable));
                        }

                        server_hc_guard.request();
                        server_hc_guard.seq
                    };

                    UdpMsg::heartbeat_encode(
                        interface_addr,
                        seq,
                        HeartbeatType::Req,
                        &mut packet,
                    );

                    key.encrypt(&mut packet, 0);
                    socket.send_to(&packet, &interface.server_addr).await?;

                    if is_p2p {
                        let node_map = interface.node_map.load_full();

                        for ext_node in node_map.values() {
                            if !ext_node.node.mode.p2p.contains(&NetProtocol::UDP) {
                                continue;
                            }

                            let is_over: bool;
                            let udp_status = **ext_node.udp_status.load();

                            let seq = {
                                let mut hc = ext_node.hc.write();
                                hc.check();
                                is_over = hc.packet_continuous_loss_count >= config.udp_heartbeat_continuous_loss;

                                if is_over && udp_status != UdpStatus::Unavailable {
                                    ext_node.udp_status.store(Arc::new(UdpStatus::Unavailable));
                                }

                                hc.request();
                                hc.seq
                            };

                            UdpMsg::heartbeat_encode(interface_addr, seq, HeartbeatType::Req, &mut packet);
                            key.encrypt(&mut packet, 0);

                            match udp_status {
                                UdpStatus::Available { dst_addr } if !is_over => {
                                    if let Err(e) = socket.send_to(&packet, dst_addr).await {
                                        return Err(anyhow!(e))
                                    }
                                }
                                _ => {
                                    if let (Some(lan), Some(wan)) = (ext_node.node.lan_udp_addr, ext_node.node.wan_udp_addr) {
                                        let addr = ext_node.peer_addr
                                            .load()
                                            .as_ref()
                                            .map(|v| **v);

                                        let packet = packet.as_slice();
                                        let rt = &*table.load_full();

                                        macro_rules! send {
                                            ($peer_addr: expr) => {
                                                if !in_routing_table(&rt, $peer_addr) {
                                                    socket.send_to(&packet, $peer_addr).await?;
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
        };

        let recv_handler = async {
            let mut buff = vec![0u8; UDP_BUFF_SIZE];

            loop {
                let (len, peer_addr) = match socket.recv_from(&mut buff).await {
                    Ok(v) => v,
                    Err(e) => {
                        #[cfg(target_os = "windows")]
                        {
                            const WSAECONNRESET: i32 = 10054;
                            const WSAENETRESET: i32 = 10052;

                            let err = e.raw_os_error();

                            if err == Some(WSAECONNRESET) ||
                                err == Some(WSAENETRESET)
                            {
                                error!("node {} receive udp packet error {}", group.node_name, e);
                                continue;
                            }
                        }
                        return Err(anyhow!(e))
                    }
                };

                let packet = &mut buff[..len];
                key.decrypt(packet, 0);

                if let Ok(packet) = UdpMsg::decode(packet) {
                    match packet {
                        UdpMsg::Heartbeat(from_addr, seq, HeartbeatType::Req) => {
                            let mut is_known = false;

                            if from_addr == SERVER_VIRTUAL_ADDR {
                                is_known = true;
                            } else if is_p2p {
                                if let Some(en) = interface.node_map.load().get(&from_addr) {
                                    let old = en.peer_addr.load().as_ref().map(|v| **v);

                                    if old != Some(peer_addr) {
                                        en.peer_addr.store(Some(Arc::new(peer_addr)));
                                    }
                                    is_known = true;
                                }
                            }

                            if is_known {
                                let interface_addr = interface.addr.load();

                                let len = UdpMsg::heartbeat_encode(
                                    interface_addr,
                                    seq,
                                    HeartbeatType::Resp,
                                    &mut buff,
                                );

                                let packet = &mut buff[..len];
                                key.encrypt(packet, 0);
                                socket.send_to(packet, peer_addr).await?;
                            }
                        }
                        UdpMsg::Heartbeat(from_addr, seq, HeartbeatType::Resp) => {
                            if from_addr == SERVER_VIRTUAL_ADDR {
                                let udp_status = **interface.server_udp_status.load();

                                match udp_status {
                                    UdpStatus::Available { dst_addr } => {
                                        if dst_addr == peer_addr {
                                            interface.server_udp_hc.write().response(seq);
                                            continue;
                                        }

                                        if lookup_host(&interface.server_addr).await == Some(peer_addr) {
                                            if interface.server_udp_hc.write().response(seq).is_some() {
                                                interface.server_udp_status.store(Arc::new(UdpStatus::Available {dst_addr: peer_addr}));
                                            }
                                        }
                                    }
                                    UdpStatus::Unavailable => {
                                        if lookup_host(&interface.server_addr).await == Some(peer_addr)  {
                                            let mut server_hc_guard = interface.server_udp_hc.write();

                                            if server_hc_guard.response(seq).is_some() &&
                                                server_hc_guard.packet_continuous_recv_count >= config.udp_heartbeat_continuous_recv
                                            {
                                                drop(server_hc_guard);
                                                interface.server_udp_status.store(Arc::new(UdpStatus::Available {dst_addr: peer_addr}));
                                            }
                                        }
                                    }
                                };
                            } else if is_p2p {
                                if let Some(node) = interface.node_map.load_full().get(&from_addr) {
                                    let mut hc_guard = node.hc.write();

                                    if hc_guard.response(seq).is_some() {
                                        if **node.udp_status.load() == UdpStatus::Unavailable &&
                                            hc_guard.packet_continuous_recv_count >= config.udp_heartbeat_continuous_recv &&
                                            !in_routing_table(&table.load(), peer_addr)
                                        {
                                            drop(hc_guard);

                                            let status = Arc::new(UdpStatus::Available {
                                                dst_addr: peer_addr,
                                            });
                                            node.udp_status.store(status);
                                        }
                                    }
                                }
                            };
                        }
                        UdpMsg::Data(packet) => {
                            if log::max_level() >= log::Level::Debug {
                                let f = || {
                                    let src = get_ip_src_addr(packet)?;
                                    let dst = get_ip_dst_addr(packet)?;
                                    Result::<_, anyhow::Error>::Ok((src, dst))
                                };

                                if let Ok((src, dst)) = f() {
                                    debug!("node {} udp handler: udp message p2p to tun; packet {}->{}", group.node_name, src, dst);
                                }
                            }

                            tun.send_packet(packet).await.context("send packet to tun error")?;
                        }
                        UdpMsg::Relay(_, packet) => {
                            if log::max_level() >= log::Level::Debug {
                                let f = || {
                                    let src = get_ip_src_addr(packet)?;
                                    let dst = get_ip_dst_addr(packet)?;
                                    Result::<_, anyhow::Error>::Ok((src, dst))
                                };

                                if let Ok((src, dst)) = f() {
                                    debug!("node {} udp handler: udp message relay to tun; packet {}->{}", group.node_name, src, dst);
                                }
                            }

                            tun.send_packet(packet).await.context("send packet to tun error")?;
                        }
                    }
                }
            }
        };

        let res: Result<((), ()), anyhow::Error> = tokio::try_join!(heartbeat_schedule, recv_handler);
        res
    });

    join.await?.with_context(|| format!("node {} udp handler error", group.node_name))?;
    Ok(())
}

#[derive(Clone, Copy)]
enum RegisterVirtualAddr {
    Manual((VirtualAddr, Ipv4Net)),
    Auto(Option<(VirtualAddr, Ipv4Net)>),
}

async fn register<T, K>(
    group: &'static TargetGroupFinalize<K>,
    stream: &mut T,
    key: &K,
    register_addr: &mut RegisterVirtualAddr,
    lan_udp_socket_addr: Option<SocketAddr>,
    refresh_route: &mut bool,
) -> Result<GroupContent>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: Cipher + Clone
{
    let mut buff = allocator::alloc(1024);

    let (virtual_addr, cidr) = match register_addr {
        RegisterVirtualAddr::Manual(addr) => *addr,
        RegisterVirtualAddr::Auto(Some(addr)) => *addr,
        RegisterVirtualAddr::Auto(None) => {
            let len = TcpMsg::get_idle_virtual_addr_encode(&mut buff);
            TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;

            let msg = TcpMsg::read_msg(stream, key, &mut buff).await?
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

    let len = TcpMsg::register_encode(&reg, &mut buff)?;
    TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;

    let ret = TcpMsg::read_msg(stream, key, &mut buff).await?
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
    Ok(group_info)
}

fn update_tun_addr<T: TunDevice, K>(
    tun: &T,
    rt: &ArcSwap<RoutingTable>,
    interface: &Interface<K>,
    old_addr: VirtualAddr,
    addr: VirtualAddr,
    old_cidr: Ipv4Net,
    cidr: Ipv4Net,
) -> Result<()> {
    rt.rcu(|v| {
        let mut t = (**v).clone();
        t.remove(&old_cidr);
        t.add(cidr, addr, interface.index);
        t
    });

    tun.delete_addr(old_addr, old_cidr.netmask())?;
    tun.add_addr(addr, cidr.netmask())?;

    interface.addr.store(addr);
    interface.cidr.store(cidr);
    Ok(())
}

async fn tcp_handler<T, K>(
    config: &'static NodeConfigFinalize<K>,
    group: &'static TargetGroupFinalize<K>,
    routing_table: Arc<ArcSwap<RoutingTable>>,
    interface: Arc<Interface<K>>,
    tun: T,
    mut channel_rx: Option<Receiver<Bytes>>,
    sys_routing: Arc<tokio::sync::Mutex<SystemRouteHandle>>,
    routes: Vec<Route>
) -> Result<()>
where
    T: TunDevice + Clone + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
{
    let join: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut sys_route_is_sync = false;
        // use defer must use atomic
        let is_add_nat = AtomicBool::new(false);
        let host_records = Mutex::new(HashSet::new());

        defer! {
            {
                let guard = host_records.lock();

                if !guard.is_empty() {
                    info!("clear node {} host records", group.node_name);

                    for host in &*guard {
                        let hb = hostsfile::HostsBuilder::new(host);

                        if let Err(e) = hb.write() {
                            error!("{}", e);
                        }
                    }
                }
            }

            if is_add_nat.load(Ordering::Relaxed) {
                info!("clear node {} nat list", group.node_name);

                if let Err(e) = del_nat(&group.allowed_ips, interface.cidr.load()) {
                    error!("{}", e);
                }
            }
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
                    VirtualAddr::UNSPECIFIED,
                    addr.ip,
                    Ipv4Net::default(),
                    cidr,
                )?;

                if !group.allowed_ips.is_empty() {
                    add_nat(&group.allowed_ips, cidr)?;
                    is_add_nat.store(true, Ordering::Relaxed);
                }

                RegisterVirtualAddr::Manual((addr.ip, cidr))
            }
        };

        let key = &group.key;

        loop {
            let mut non_retryable = false;

            let process = async {
                let mut stream = TcpStream::connect(&group.server_addr)
                    .await
                    .with_context(|| format!("connect to {} error", &group.server_addr))?;

                let mut refresh_route= false;

                let group_info = tokio::time::timeout(
                    Duration::from_secs(30),
                    register(
                        group,
                        &mut stream,
                        key,
                        &mut tun_addr,
                        lan_udp_socket_addr,
                        &mut refresh_route
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
                                old_addr,
                                *addr,
                                old_cidr,
                                *cidr,
                            )?;

                            if !group.allowed_ips.is_empty() {
                                if old_cidr != *cidr &&
                                    is_add_nat.load(Ordering::Relaxed)
                                {
                                    del_nat(&group.allowed_ips,old_cidr)?;
                                    is_add_nat.store(false, Ordering::Relaxed);
                                }

                                if !is_add_nat.load(Ordering::Relaxed) {
                                    add_nat(&group.allowed_ips, *cidr)?;
                                    is_add_nat.store(true, Ordering::Relaxed);
                                }
                            }
                            Result::<_, anyhow::Error>::Ok(())
                        };

                        if let Err(e) = f() {
                            non_retryable = true;
                            return Err(e);
                        }
                    }
                }

                interface.group_name.store(Some(Arc::new(group_info.name.clone())));

                // tun must first set the ip address
                if !sys_route_is_sync {
                    let res = sys_routing.lock().await.add(&routes).await;

                    if let Err(e) = res {
                        non_retryable = true;
                        return Err(e);
                    }

                    sys_route_is_sync = true;
                }

                interface.server_is_connected.store(true, Ordering::Relaxed);
                info!("node {}({}) has joined group {}", group.node_name, interface.addr.load(), group_info.name);
                info!("group {} address range {}", group_info.name, group_info.cidr);

                let (rx, mut tx) = stream.split();
                let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

                let (inner_channel_tx, mut inner_channel_rx) = unbounded_channel::<Bytes>();

                let recv_handler = async {
                    let mut buff = vec![0u8; TCP_BUFF_SIZE];

                    loop {
                        let msg = TcpMsg::read_msg(&mut rx, key, &mut buff).await?
                            .ok_or_else(|| anyhow!("server connection closed"))?;

                        match msg {
                            TcpMsg::NodeMap(map) => {
                                let mut new_map = HashMap::new();

                                {
                                    let old_map = interface.node_map.load();

                                    for (virtual_addr, node) in map {
                                        match old_map.get(&virtual_addr) {
                                            None => {
                                                new_map.insert(virtual_addr, ExtendedNode::from(node));
                                            },
                                            Some(v) => {
                                                let en = ExtendedNode {
                                                    node,
                                                    hc: v.hc.clone(),
                                                    udp_status: v.udp_status.clone(),
                                                    peer_addr: v.peer_addr.clone()
                                                };
                                                new_map.insert(virtual_addr, en);
                                            }
                                        }
                                    }
                                }

                                let host_key = format!("FUBUKI-{}", group_info.name);
                                let mut hb = hostsfile::HostsBuilder::new(&host_key);
                                host_records.lock().insert(host_key);

                                for node in new_map.values() {
                                    let node = &node.node;
                                    hb.add_hostname(IpAddr::from(node.virtual_addr), format!("{}.{}", &node.name, &group_info.name));
                                }

                                tokio::task::spawn_blocking(move || {
                                    let node_name = &group.node_name;

                                    match hb.write() {
                                        Ok(_) => info!("node {} update hosts", node_name),
                                        Err(e) => error!("node {} update hosts error: {}", node_name, e)
                                    }
                                });

                                interface.node_map.store(Arc::new(new_map));
                            }
                            TcpMsg::Relay(_, buff) => {
                                if log::max_level() >= log::Level::Debug {
                                    let f = || {
                                        let src = get_ip_src_addr(buff)?;
                                        let dst = get_ip_dst_addr(buff)?;
                                        Result::<_, anyhow::Error>::Ok((src, dst))
                                    };

                                    if let Ok((src, dst)) = f() {
                                        debug!("node {} tcp handler: tcp message relay to tun; packet {}->{}", group.node_name, src, dst);
                                    }
                                }

                                tun.send_packet(buff).await?;
                            }
                            TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                                TcpMsg::heartbeat_encode(seq, HeartbeatType::Resp, &mut buff);
                                key.encrypt(&mut buff, 0);

                                let res = inner_channel_tx
                                    .send(buff)
                                    .map_err(|e| anyhow!(e.to_string()));

                                if res.is_err() {
                                    return res;
                                }
                            }
                            TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                                interface.server_tcp_hc.write().response(recv_seq);
                            }
                            _ => continue,
                        }
                    }
                };

                let send_handler = async {
                    loop {
                        tokio::select! {
                            opt = inner_channel_rx.recv() => {
                                match opt {
                                    Some(buff) => tx.write_all(&buff).await?,
                                    None => return Ok(())
                                };
                            }
                            opt = match channel_rx {
                                Some(ref mut v) => v.recv().right_future(),
                                None => std::future::pending().left_future()
                            } => {
                                match opt {
                                    Some(buff) => tx.write_all(&buff).await?,
                                    None => return Ok(())
                                };
                            }
                        }
                    }
                };

                let heartbeat_schedule = async {
                    loop {
                        let seq = {
                            let mut guard = interface.server_tcp_hc.write();
                            guard.check();

                            if guard.packet_continuous_loss_count >= config.tcp_heartbeat_continuous_loss {
                                guard.packet_continuous_loss_count = 0;
                                return Result::<(), _>::Err(anyhow!("receive tcp heartbeat timeout"));
                            }

                            guard.request();
                            guard.seq
                        };

                        let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                        TcpMsg::heartbeat_encode(seq, HeartbeatType::Req, &mut buff);
                        key.encrypt(&mut buff, 0);
                        inner_channel_tx.send(buff).map_err(|e| anyhow!(e.to_string()))?;

                        tokio::time::sleep(config.tcp_heartbeat_interval).await;
                    }
                };

                tokio::try_join!(recv_handler, send_handler, heartbeat_schedule)?;
                Result::<_, anyhow::Error>::Ok(())
            };

            if let Err(e) = process.await {
                if non_retryable {
                    return Err(e)
                }
                error!("node {} tcp handler error: {:?}", &group.node_name, e)
            }

            interface.server_is_connected.store(false, Ordering::Relaxed);
            time::sleep(config.reconnect_interval).await;
        }
    });

    join.await?.with_context(|| format!("node {} tcp handler error", group.node_name))
}

pub async fn start<K>(config: NodeConfigFinalize<K>) -> Result<()>
    where
        K: Cipher + Send + Sync + Clone + 'static
{
    let config = &*Box::leak(Box::new(config));

    let tun = Arc::new(tun::create()?);
    tun.set_mtu(config.mtu)?;

    let mut rt = RoutingTable::new();

    for (index, group) in config.groups.iter().enumerate() {
        for (dst, cidrs) in &group.ips {
            for cidr in cidrs {
                rt.add(*cidr, *dst, index);
            }
        }
    }

    let rt = Arc::new(ArcSwap::from_pointee(rt));

    let mut future_list: Vec<LocalBoxFuture<Result<()>>> = Vec::new();
    let mut interfaces = Vec::with_capacity(config.groups.len());
    let sys_routing = Arc::new(tokio::sync::Mutex::new(SystemRouteHandle::new()?));
    let tun_index = tun.get_index();

    for (index, group) in config.groups.iter().enumerate() {
        let (channel_tx, channel_rx) = if group.mode.is_use_tcp() {
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(config.channel_limit);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let udp_opt = match group.lan_ip_addr {
            Some(lan_ip_addr) if group.mode.is_use_udp() => {
                let bind_addr = match lan_ip_addr {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                };

                let udp_socket = UdpSocket::bind((bind_addr, 0))
                    .await
                    .context("create udp socket failed")?;

                if let Some(v) = config.udp_socket_recv_buffer_size {
                    udp_socket.set_recv_buffer_size(v)?;
                }

                if let Some(v) = config.udp_socket_send_buffer_size {
                    udp_socket.set_send_buffer_size(v)?;
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
            node_map: ArcSwap::from_pointee(HashMap::new()),
            server_addr: group.server_addr.clone(),
            server_udp_hc: RwLock::new(HeartbeatCache::new()),
            server_udp_status: ArcSwap::from_pointee(UdpStatus::Unavailable),
            server_tcp_hc: RwLock::new(HeartbeatCache::new()),
            server_is_connected: AtomicBool::new(false),
            tcp_handler_channel: channel_tx,
            udp_socket: udp_opt,
            key: group.key.clone()
        };

        let interface = Arc::new(interface);
        interfaces.push(interface.clone());

        let mut routes = Vec::new();

        for (gateway, cidrs) in &group.ips {
            for cidr in cidrs {
                let route = Route::new(IpAddr::V4(cidr.network()), cidr.prefix_len())
                    .with_gateway(IpAddr::V4(*gateway))
                    .with_ifindex(tun_index);

                routes.push(route);
            }
        }

        let fut = tcp_handler(
            config,
            group,
            rt.clone(),
            interface.clone(),
            tun.clone(),
            channel_rx,
            sys_routing.clone(),
            routes
        );
        future_list.push(Box::pin(fut));

        if interface.udp_socket.is_some() {
            let fut = udp_handler(
                config,
                group,
                rt.clone(),
                interface,
                tun.clone(),
            );
            future_list.push(Box::pin(fut));
        }
    };

    let tun_handler_fut = tun_handler(tun, rt, interfaces.clone());
    future_list.push(Box::pin(tun_handler_fut));
    future_list.push(Box::pin(api_start(config.api_addr, interfaces)));

    let serve = futures_util::future::try_join_all(future_list);

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

    Ok(())
}

pub(crate) async fn info(api_addr: &str, info_type: NodeInfoType) -> Result<()> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}/info", api_addr))
        .body(Body::empty())?;

    let c = hyper::client::Client::new();
    let resp = c.request(req).await?;

    let (parts, body) = resp.into_parts();

    if parts.status != 200 {
        let bytes = hyper::body::to_bytes(body).await?;
        let msg = String::from_utf8(bytes.to_vec())?;
        return Err(anyhow!("http response code: {}, message: {}", parts.status.as_u16(), msg));
    }

    let body = hyper::body::aggregate(body).await?;
    let interfaces_info: Vec<InterfaceInfo> = serde_json::from_reader(body.reader())?;

    let mut table = Table::new();

    match info_type {
        NodeInfoType::Interface{ index: None } => {
            table.add_row(row!["INDEX", "NAME", "GROUP", "IP"]);

            for info in interfaces_info {
                table.add_row(row![
                    info.index,
                    info.node_name,
                    info.group_name.unwrap_or_default(),
                    info.addr,
                ]);
            }
        }
        NodeInfoType::Interface{ index: Some(index) } => {
            for info in interfaces_info {
                if info.index == index {
                    table.add_row(row!["INDEX", info.index]);
                    table.add_row(row!["NAME", info.node_name]);
                    table.add_row(row!["GROUP", info.group_name.unwrap_or_default()]);
                    table.add_row(row!["IP", info.addr]);
                    table.add_row(row!["CIDR", info.cidr]);
                    table.add_row(row!["SERVER_ADDRESS", info.server_addr]);
                    table.add_row(row!["PROTOCOL_MODE", format!("{:?}", info.mode)]);
                    table.add_row(row!["IS_CONNECTED", info.server_is_connected]);
                    table.add_row(row!["UDP_STATUS", info.server_udp_status]);
                    table.add_row(row!["UDP_LATENCY", format!("{:?}", info.server_udp_hc.elapsed)]);
                    table.add_row(row!["UDP_LOSS_RATE", format!("{}%", info.server_udp_hc.packet_loss_count as f32 / info.server_udp_hc.send_count as f32 * 100f32)]);
                    table.add_row(row!["TCP_LATENCY", format!("{:?}", info.server_tcp_hc.elapsed)]);
                    table.add_row(row!["TCP_LOSS_RATE", format!("{}%", info.server_tcp_hc.packet_loss_count as f32 / info.server_tcp_hc.send_count as f32 * 100f32)]);

                    break;
                }
            }
        }
        NodeInfoType::NodeMap{ interface_index, node_ip: None } => {
            table.add_row(row!["NAME", "IP", "REGISTER_TIME"]);

            for info in interfaces_info {
                if info.index == interface_index {
                    for node in info.node_map.values() {
                        let register_time = utc_to_str(node.node.register_time)?;

                        table.add_row(row![
                            node.node.name,
                            node.node.virtual_addr,
                            register_time,
                        ]);
                    }
                    break;
                }
            }
        }
        NodeInfoType::NodeMap{ interface_index, node_ip: Some(ip) } => {
            for info in interfaces_info {
                if info.index == interface_index {
                    if let Some(node) = info.node_map.get(&ip) {
                        let register_time = utc_to_str(node.node.register_time)?;

                        table.add_row(row!["NAME", node.node.name]);
                        table.add_row(row!["IP", node.node.virtual_addr]);
                        table.add_row(row!["LAN_ADDRESS", format!("{:?}", node.node.lan_udp_addr)]);
                        table.add_row(row!["WAN_ADDRESS", format!("{:?}", node.node.wan_udp_addr)]);
                        table.add_row(row!["PROTOCOL_MODE",  format!("{:?}", node.node.mode)]);
                        table.add_row(row!["ALLOWED_IPS",  format!("{:?}", node.node.allowed_ips)]);
                        table.add_row(row!["REGISTER_TIME", register_time]);
                        table.add_row(row!["UDP_STATUS", node.udp_status]);
                        table.add_row(row!["LATENCY", format!("{:?}", node.hc.elapsed)]);
                        table.add_row(row!["LOSS_RATE", format!("{}%", node.hc.packet_loss_count as f32 / node.hc.send_count as f32 * 100f32)]);
                    }

                    break;
                }
            }
        }
    }

    table.printstd();
    Ok(())
}