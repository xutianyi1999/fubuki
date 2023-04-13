use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use ahash::{HashMap, HashMapExt};
use anyhow::{anyhow, Context as AnyhowContext};
use anyhow::Result;
use arc_swap::{ArcSwap, ArcSwapOption, Cache};
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use futures_util::future::LocalBoxFuture;
use futures_util::FutureExt;
use hyper::{Body, Method, Request};
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use prettytable::{row, Table};
use rand::random;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::mpsc::{Receiver, Sender, unbounded_channel};
use tokio::time;
use hyper::body::Buf;
use net_route::Route;
use scopeguard::defer;

use crate::{Cipher, ClientConfigFinalize, ProtocolMode, NodeInfoType, TargetGroupFinalize};
use crate::client::api::api_start;
use crate::client::sys_route::SystemRouteHandle;
use crate::common::{allocator, net};
use crate::common::allocator::Bytes;
use crate::common::net::{HeartbeatCache, HeartbeatInfo, protocol, SocketExt, UdpStatus};
use crate::common::net::protocol::{AllocateError, GroupInfo, HeartbeatType, NetProtocol, Node, Register, RegisterResult, Seq, SERVER_VIRTUAL_ADDR, TCP_BUFF_SIZE, TCP_MSG_HEADER_LEN, TcpMsg, UDP_BUFF_SIZE, UDP_MSP_HEADER_LEN, UdpMsg, VirtualAddr};
use crate::common::routing_table::RoutingTable;
use crate::tun::create_device;
use crate::tun::TunDevice;

mod api;
mod nat;
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
        let inner: AtomicU64 = unsafe {
            std::mem::transmute(Inner { v: value })
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
    // todo use ArcSwap
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
            udp_status: (**value.udp_status.load()),
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
    if (!inter.mode.direct.is_empty()) && (!dst_node.node.mode.direct.is_empty()) {
        let udp_status = **dst_node.udp_status.load();

        if let UdpStatus::Available { dst_addr } = udp_status {
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
                    let mut packet = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + packet_range.len());
                    packet[DATA_START..].copy_from_slice(&buff[packet_range.start..packet_range.end]);

                    TcpMsg::relay_encode(dst_node.node.virtual_addr, packet_range.len(), &mut packet);
                    inter.key.encrypt(&mut packet, 0);

                    match tx.try_send(packet) {
                        Ok(_) => return Ok(()),
                        Err(e) => error!("{}", e)
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

                    let packet = &mut buff[packet_range.start - size_of::<VirtualAddr>() - UDP_MSP_HEADER_LEN..packet_range.end];

                    UdpMsg::relay_encode(dst_node.node.virtual_addr, packet_range.len(), packet);
                    inter.key.encrypt(packet, 0);
                    socket.send_to(packet, dst_addr).await?;
                    return Ok(())
                }
            };
        }
    }

    warn!("No route to {}", dst_node.node.virtual_addr);
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
    let join = tokio::spawn(async move {
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
                .context("Read packet from tun error")?
            {
                0 => continue,
                len => &buff[START..START + len],
            };

            let packet_range = START..START + data.len();
            let src_addr = protocol::get_ip_src_addr(data)?;
            let dst_addr = protocol::get_ip_dst_addr(data)?;

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

            let inter = &interfaces[item.interface_index];

            match transfer_type {
                TransferType::Unicast(addr) => {
                    if interface_addr == addr {
                        tun.send_packet(data).await.context("Write packet to tun error")?;
                        continue;
                    }

                    let node = match node_map.get(&addr) {
                        None => continue,
                        Some(node) => node
                    };

                    debug!("{} -> {}; gateway: {}", src_addr, dst_addr, addr);
                    send(inter, node, server_us, &mut buff, packet_range).await?
                }
                TransferType::Broadcast => {
                    debug!("{} -> {}", src_addr, dst_addr);

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
    join.await?
}

async fn udp_handler<T, K>(
    config: &'static ClientConfigFinalize<K>,
    interface: Arc<Interface<K>>,
    tun: T,
) -> Result<()>
where
    T: TunDevice + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
{
    let join = tokio::spawn(async move {
        let socket = interface.udp_socket.as_ref().expect("Must need udp socket");
        let key = &interface.key;
        let is_direct = interface.mode.direct.contains(&NetProtocol::UDP);

        let heartbeat_schedule =  async {
            let mut packet = vec![0u8; UDP_MSP_HEADER_LEN + size_of::<VirtualAddr>() + size_of::<Seq>() + size_of::<HeartbeatType>()];
            let mut is_send = false;

            loop {
                let interface_addr = interface.addr.load();

                if !interface_addr.is_unspecified() {
                    let server_hc = &interface.server_udp_hc;
                    let seq = {
                        let mut server_hc_guard = server_hc.write();

                        if is_send {
                            server_hc_guard.check();

                            if server_hc_guard.packet_continuous_loss_count >= config.udp_heartbeat_continuous_loss && **interface.server_udp_status.load() != UdpStatus::Unavailable {
                                interface.server_udp_status.store(Arc::new(UdpStatus::Unavailable));
                            }
                        }

                        server_hc_guard.increment();
                        server_hc_guard.seq
                    };

                    is_send = true;

                    UdpMsg::heartbeat_encode(
                        interface_addr,
                        seq,
                        HeartbeatType::Req,
                        &mut packet,
                    );

                    key.encrypt(&mut packet, 0);
                    socket.send_to(&packet, &interface.server_addr).await?;

                    if is_direct {
                        let node_map = interface.node_map.load_full();

                        for (_, ext_node) in &*node_map {
                            if !ext_node.node.mode.direct.contains(&NetProtocol::UDP) {
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

                                hc.increment();
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
                                    if let (Some(lan), Some(wan)) =
                                        (ext_node.node.lan_udp_addr, ext_node.node.wan_udp_addr)
                                    {
                                        let addr = ext_node.peer_addr
                                            .load()
                                            .as_ref()
                                            .map(|v| **v);

                                        if let Some(addr) = addr {
                                            if addr != lan && addr != wan {
                                                socket.send_to(&packet, addr).await?;
                                            }
                                        }

                                        if wan == lan {
                                            socket.send_to(&packet, lan).await?;
                                        } else {
                                            socket.send_to(&packet, lan).await?;
                                            socket.send_to(&packet, wan).await?;
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

                            if e.raw_os_error() == Some(WSAECONNRESET) {
                                error!("Receive udp packet error {}", e);
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
                            } else if is_direct {
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
                                match &*interface.server_udp_status.load_full() {
                                    UdpStatus::Available { dst_addr } => {
                                        if *dst_addr == peer_addr {
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

                                            if server_hc_guard.response(seq).is_some() && server_hc_guard.packet_continuous_recv_count >= config.udp_heartbeat_continuous_recv {
                                                drop(server_hc_guard);
                                                interface.server_udp_status.store(Arc::new(UdpStatus::Available {dst_addr: peer_addr}));
                                            }
                                        }
                                    }
                                };
                            } else if is_direct {
                                if let Some(node) = interface.node_map.load_full().get(&from_addr) {
                                    let mut hc_guard = node.hc.write();

                                    if hc_guard.response(seq).is_some() {
                                        if **node.udp_status.load() == UdpStatus::Unavailable && hc_guard.packet_continuous_recv_count >= config.udp_heartbeat_continuous_recv
                                        {
                                            drop(hc_guard);
                                            let status = Arc::new(UdpStatus::Available {
                                                dst_addr: peer_addr,
                                            });
                                            node.udp_status.store(status);
                                        }
                                    }
                                    continue;
                                }
                            };
                        }
                        UdpMsg::Data(packet) => {
                            debug!("Recv packet from {}", peer_addr);

                            tun.send_packet(packet).await.context("Write packet to tun error")?;
                        }
                        UdpMsg::Relay(_, packet) => {
                            let src = net::protocol::get_ip_src_addr(packet)?;
                            let dst= net::protocol::get_ip_dst_addr(packet)?;

                            debug!("Recv packet from {}; {}->{}", peer_addr, src, dst);

                            tun.send_packet(packet).await.context("Write packet to tun error")?;
                        }
                    }
                }
            }
        };
        let res: Result<((), ()), anyhow::Error> = tokio::try_join!(heartbeat_schedule, recv_handler);
        res
    });
    join.await??;
    Ok(())
}

#[derive(Clone, Copy)]
enum RegisterVirtualAddr {
    Manual((VirtualAddr, Ipv4Net)),
    Auto(Option<(VirtualAddr, Ipv4Net)>),
}

async fn register<T, K>(
    config: &'static ClientConfigFinalize<K>,
    group: &'static TargetGroupFinalize<K>,
    stream: &mut T,
    key: &K,
    register_addr: &mut RegisterVirtualAddr,
    lan_udp_socket_addr: Option<SocketAddr>,
    refresh_route: &mut bool,
) -> Result<GroupInfo>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: Cipher + Clone
{
    let mut buff = allocator::alloc(1024);

    let (virtual_addr, cidr) = match register_addr {
        RegisterVirtualAddr::Manual(addr) => *addr,
        RegisterVirtualAddr::Auto(Some(addr)) => *addr,
        RegisterVirtualAddr::Auto(None) => {
            *refresh_route = true;
            let len = TcpMsg::get_idle_virtual_addr_encode(&mut buff);
            TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;

            let msg = TcpMsg::read_msg(stream, key, &mut buff).await?
                .ok_or_else(|| anyhow!("Server connection closed"))?;

            match msg {
                TcpMsg::GetIdleVirtualAddrRes(Some((addr, cidr))) => {
                    *register_addr = RegisterVirtualAddr::Auto(Some((addr, cidr)));
                    (addr, cidr)
                },
                TcpMsg::GetIdleVirtualAddrRes(None) => return Err(anyhow!("Insufficient address pool")),
                _ => return Err(anyhow!("Invalid Message")),
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
        allowed_ips: config.allowed_ips.clone()
    };

    let len = TcpMsg::register_encode(&reg, &mut buff)?;
    TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;

    let ret = TcpMsg::read_msg(stream, key, &mut buff).await?
        .ok_or_else(|| anyhow!("Server connection closed"))?;

    let group_info = match ret {
        TcpMsg::RegisterRes(RegisterResult::Success(group_info)) => group_info,
        TcpMsg::RegisterRes(RegisterResult::Timeout) => return Err(anyhow!("Register timeout")),
        TcpMsg::RegisterRes(RegisterResult::NonceRepeat) => return Err(anyhow!("Nonce repeat")),
        TcpMsg::RegisterRes(RegisterResult::InvalidVirtualAddress(e)) => {
            if e == AllocateError::IpAlreadyInUse {
                if let RegisterVirtualAddr::Auto(v) = register_addr {
                    *v = None;
                }
            }
            return Err(anyhow!(e))
        }
        _ => return Err(anyhow!("Response message not match")),
    };

    if cidr != group_info.cidr {
        return Err(anyhow!("Cidr not match"));
    }
    Ok(group_info)
}

fn update_tun_addr<T: TunDevice, K>(
    tun: &T,
    rt: &ArcSwap<RoutingTable>,
    addr: VirtualAddr,
    cidr: Ipv4Net,
    interface: &Interface<K>
) -> Result<()> {
    rt.rcu(|v| {
        let mut t = (**v).clone();
        t.remove(&cidr);
        t.add(cidr, addr, interface.index);
        t
    });

    tun.delete_addr(addr, cidr.netmask())?;
    tun.add_addr(addr, cidr.netmask())?;

    interface.addr.store(addr);
    interface.cidr.store(cidr);
    Ok(())
}

async fn tcp_handler<T, K>(
    config: &'static ClientConfigFinalize<K>,
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
    let join = tokio::spawn(async move {
        let mut sys_route_is_sync = false;

        let lan_udp_socket_addr = match (&interface.udp_socket, &group.lan_ip_addr) {
            (Some(s), Some(lan_ip)) => Some(SocketAddr::new(*lan_ip, s.local_addr()?.port())),
            _ => None,
        };

        let mut tun_addr = match &group.tun_addr {
            None => RegisterVirtualAddr::Auto(None),
            Some(addr) => {
                let cidr = Ipv4Net::with_netmask(addr.ip, addr.netmask)?.trunc();
                update_tun_addr(&tun, &routing_table, addr.ip, cidr, &*interface)?;
                RegisterVirtualAddr::Manual((addr.ip, cidr))
            }
        };

        let key = &group.key;

        loop {
            let process = async {
                let mut stream = TcpStream::connect(&group.server_addr)
                    .await
                    .with_context(|| format!("Connect to {} error", &group.server_addr))?;

                let mut refresh_route= false;

                let group_info = tokio::time::timeout(
                    Duration::from_secs(30),
                    register(
                        config,
                        group,
                        &mut stream,
                        key,
                        &mut tun_addr,
                        lan_udp_socket_addr,
                        &mut refresh_route
                    )
                ).await??;

                if refresh_route {
                    if let RegisterVirtualAddr::Auto(Some((addr, cidr))) = &tun_addr {
                        update_tun_addr(&tun, &routing_table, *addr, *cidr, &*interface)?;
                    }
                }

                interface.group_name.store(Some(Arc::new(group_info.name.clone())));
                interface.server_is_connected.store(true, Ordering::Relaxed);

                if !sys_route_is_sync {
                    sys_route_is_sync = true;
                    sys_routing.lock().await.add(&routes).await?;
                }

                info!("Server {} connected", group.server_addr);

                let (rx, mut tx) = stream.split();
                let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

                let (inner_channel_tx, mut inner_channel_rx) = unbounded_channel::<Bytes>();

                let recv_handler = async {
                    let mut buff = vec![0u8; TCP_BUFF_SIZE];

                    loop {
                        let msg = TcpMsg::read_msg(&mut rx, key, &mut buff).await?
                            .ok_or_else(|| anyhow!("Server connection closed"))?;

                        match msg {
                            TcpMsg::NodeMap(map) => {
                                let old_map = interface.node_map.load_full();
                                let mut new_map = HashMap::new();

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

                                let new_map = Arc::new(new_map);
                                interface.node_map.store(new_map.clone());

                                let mut hb = hostsfile::HostsBuilder::new("FUBUKI");

                                for node in new_map.values() {
                                    let node = &node.node;
                                    hb.add_hostname(IpAddr::from(node.virtual_addr), format!("{}.{}", &node.name, &group_info.name));
                                }

                                tokio::task::spawn_blocking(move || {
                                    match hb.write() {
                                        Ok(_) => info!("Update hosts file"),
                                        Err(e) => error!("Update hosts file error: {}", e)
                                    }
                                });
                            }
                            TcpMsg::Relay(_, buff) => {
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
                    let mut is_send = false;

                    loop {
                        let seq = {
                            let mut guard = interface.server_tcp_hc.write();

                            if is_send {
                                guard.check();

                                if guard.packet_continuous_loss_count >= config.tcp_heartbeat_continuous_loss {
                                    guard.packet_continuous_loss_count = 0;
                                    return Result::<(), _>::Err(anyhow!("Recv tcp heartbeat timeout"));
                                }
                            }

                            guard.increment();
                            guard.seq
                        };

                        is_send = true;

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
                error!("{} TCP node handler error -> {:?}", &group.server_addr, e)
            }

            interface.server_is_connected.store(false, Ordering::Relaxed);
            time::sleep(config.reconnect_interval).await;
        }
    });
    join.await?
}

pub async fn start<K: >(config: ClientConfigFinalize<K>) -> Result<()>
    where
        K: Cipher + Send + Sync + Clone + 'static
{
    let config = &*Box::leak(Box::new(config));

    let tun = Arc::new(create_device()?);
    tun.set_mtu(config.mtu)?;

    if !config.allowed_ips.is_empty() {
        nat::add_nat(&config.allowed_ips)?;
    }

    defer! {
        if !config.allowed_ips.is_empty() {
            info!("Clear nat list");

            if let Err(e) = nat::del_nat(&config.allowed_ips) {
                error!("{}", e);
            }
        }
    }

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
                    .context("Failed to create UDP socket")?;

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
                interface,
                tun.clone(),
            );
            future_list.push(Box::pin(fut));
        }
    };

    let tun_handler_fut = tun_handler(tun.clone(), rt, interfaces.clone());
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
        return Err(anyhow!("HTTP response code: {}, message: {}", parts.status.as_u16(), msg));
    }

    let body = hyper::body::aggregate(body).await?;
    let interfaces_info: Vec<InterfaceInfo> = serde_json::from_reader(body.reader())?;

    let mut table = Table::new();

    match info_type {
        NodeInfoType::Interface => {
            table.add_row(row!["INDEX", "NAME", "GROUP", "IP", "CIDR", "SERVER_ADDRESS", "IS_CONNECTED", "UDP_STATUS", "UDP DELAY&LOSS_RATE", "TCP DELAY&LOSS_RATE", "PROTOCOL_MODE"]);

            for info in interfaces_info {
                table.add_row(row![
                    info.index,
                    info.node_name,
                    format!("{:?}", info.group_name),
                    info.addr,
                    info.cidr,
                    info.server_addr,
                    info.server_is_connected,
                    info.server_udp_status,
                    format!("{:?}-{}%", info.server_udp_hc.elapsed, info.server_udp_hc.packet_loss_count as f32 / info.server_udp_hc.send_count as f32 * 100f32),
                    format!("{:?}-{}%", info.server_tcp_hc.elapsed, info.server_tcp_hc.packet_loss_count as f32 / info.server_tcp_hc.send_count as f32 * 100f32),
                    format!("{:?}", info.mode)
                ]);
            }
        }
        NodeInfoType::NodeMap{interface_id} => {
            table.add_row(row!["NAME", "IP", "LAN_ADDRESS", "WAN_ADDRESS", "PROTOCOL_MODE", "ALLOWED_IPS", "REGISTER_TIME", "UDP_STATUS", "UDP DELAY&LOSS_RATE"]);

            for info in interfaces_info {
                if info.index == interface_id {
                    for (_, node) in info.node_map {
                        let register_time = {
                            let utc: DateTime<Utc> = DateTime::from_utc(
                                NaiveDateTime::from_timestamp_opt(node.node.register_time, 0).ok_or_else(|| anyhow!("Can't convert timestamp"))?,
                                Utc,
                            );
                            let local_time: DateTime<Local> = DateTime::from(utc);
                            local_time.format("%Y-%m-%d %H:%M:%S").to_string()
                        };

                        table.add_row(row![
                            node.node.name,
                            node.node.virtual_addr,
                            format!("{:?}", node.node.lan_udp_addr),
                            format!("{:?}", node.node.wan_udp_addr),
                            format!("{:?}", node.node.mode),
                            format!("{:?}", node.node.allowed_ips),
                            register_time,
                            node.udp_status,
                            format!("{:?}-{}%", node.hc.elapsed, node.hc.packet_loss_count as f32 / node.hc.send_count as f32 * 100f32),
                        ]);
                    }
                    break;
                }
            }
        }
    }

    table.printstd();
    Ok(())
}