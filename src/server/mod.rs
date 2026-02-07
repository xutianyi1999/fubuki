use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use chrono::Utc;
use crossbeam_utils::atomic::AtomicCell;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, DuplexStream};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, watch};
use tokio::{sync, time};

use crate::common::allocator::Bytes;
use crate::common::cipher::Cipher;
use crate::common::net::protocol::{AllocateError, GroupContent, HeartbeatType, NetProtocol, Node, PeerStatus, Register, RegisterError, Seq, TcpMsg, UdpMsg, UdpSocketErr, VirtualAddr, SERVER_VIRTUAL_ADDR, TCP_BUFF_SIZE, TCP_MSG_HEADER_LEN, UDP_BUFF_SIZE, UDP_MSG_HEADER_LEN};
use crate::common::net::{get_ip_dst_addr, get_ip_src_addr, FlowControl, HeartbeatCache, HeartbeatInfo, PushResult, SocketExt, UdpStatus};
use crate::common::{allocator};
use crate::kcp_bridge::KcpStack;
use crate::server::api::api_start;
use crate::server::info_tui::App;
use crate::ServerConfigFinalize;
use crate::{GroupFinalize};

mod api;
mod info_tui;

pub type NodeMap = HashMap<VirtualAddr, Node>;

struct NodeHandle {
    node: ArcSwap<Node>,
    udp_status: AtomicCell<UdpStatus>,
    udp_heartbeat_cache: RwLock<HeartbeatCache>,
    tcp_heartbeat_cache: RwLock<HeartbeatCache>,
    // (peers, update time)
    peers_status: RwLock<Option<(Vec<PeerStatus>, Instant)>>,
    tx: Sender<Bytes>,
}

#[derive(Serialize, Deserialize, Clone)]
struct NodeInfo {
    node: Node,
    udp_status: UdpStatus,
    udp_heartbeat_cache: HeartbeatInfo,
    tcp_heartbeat_cache: HeartbeatInfo
}

impl From<&NodeHandle> for NodeInfo {
    fn from(value: &NodeHandle) -> Self {
        NodeInfo {
            node: (**value.node.load()).clone(),
            udp_status: value.udp_status.load(),
            udp_heartbeat_cache: HeartbeatInfo::from(&*value.udp_heartbeat_cache.read()),
            tcp_heartbeat_cache: HeartbeatInfo::from(&*value.tcp_heartbeat_cache.read())
        }
    }
}

struct Bridge {
    channel_rx: Receiver<Bytes>,
    watch_rx: watch::Receiver<Arc<HashMap<VirtualAddr, Node>>>,
}

struct GroupHandle {
    name: String,
    listen_addr: SocketAddr,
    address_range: Ipv4Net,
    limit: usize,
    mapping: RwLock<HashMap<VirtualAddr, Arc<NodeHandle>>>,
    watch: (watch::Sender<Arc<NodeMap>>, watch::Receiver<Arc<NodeMap>>),
    flow_control: FlowControl
}

impl GroupHandle {
    fn new<K>(
        channel_limit: usize,
        group_config: &GroupFinalize<K>,
    ) -> Self {
        GroupHandle {
            name: group_config.name.clone(),
            listen_addr: group_config.listen_addr,
            address_range: group_config.address_range,
            limit: channel_limit,
            mapping: RwLock::new(HashMap::new()),
            watch: watch::channel(Arc::new(HashMap::new())),
            flow_control: FlowControl::new(group_config.flow_control_rules.clone())
        }
    }

    fn join(&self, node: Node) -> Result<(Bridge, Arc<NodeHandle>)> {
        let (_, watch_rx) = &self.watch;
        let (tx, rx) = mpsc::channel(self.limit);

        let mut mp_guard = self.mapping.write();
        let vaddr = node.virtual_addr;

        let node_handle = NodeHandle {
            node: ArcSwap::from_pointee(node),
            tx,
            udp_status: AtomicCell::new(UdpStatus::Unavailable),
            udp_heartbeat_cache: RwLock::new(HeartbeatCache::new()),
            tcp_heartbeat_cache: RwLock::new(HeartbeatCache::new()),
            peers_status: RwLock::new(None)
        };

        let node_handle = Arc::new(node_handle);

        mp_guard.insert(
            vaddr,
            node_handle.clone()
        );
        self.sync(&mp_guard)?;
        drop(mp_guard);

        self.flow_control.add_address(vaddr);

        let bridge = Bridge {
            channel_rx: rx,
            watch_rx: watch_rx.clone(),
        };
        Ok((bridge, node_handle))
    }

    fn sync(&self, node_map: &HashMap<VirtualAddr, Arc<NodeHandle>>) -> Result<()> {
        let (tx, _) = &self.watch;

        let node_list: HashMap<VirtualAddr, Node> = node_map
            .iter()
            .map(|(addr, handle)| (*addr, (**handle.node.load()).clone()))
            .collect();

        tx.send(Arc::new(node_list))
            .map_err(|_| anyhow!("sync node_map error"))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct GroupInfo {
    name: String,
    listen_addr: SocketAddr,
    address_range: Ipv4Net,
    node_map: HashMap<VirtualAddr, NodeInfo>
}

impl From<&GroupHandle> for GroupInfo {
    fn from(value: &GroupHandle) -> Self {
        GroupInfo {
            name: value.name.clone(),
            listen_addr: value.listen_addr,
            address_range: value.address_range,
            node_map: {
                value.mapping.read()
                    .iter()
                    .map(|(k, v)| (*k, NodeInfo::from(&**v)))
                    .collect()
            }
        }
    }
}

async fn udp_handler<K: Cipher + Clone + Send + Sync>(
    group: &'static GroupFinalize<K>,
    socket: Arc<UdpSocket>,
    group_handle: Arc<GroupHandle>,
    heartbeat_interval: Duration,
    packet_loss_limit: u64,
    packet_continuous_recv: u64,
    notified: watch::Receiver<()>,
    kcp_acceptor_channel: mpsc::Sender<(DuplexStream, SocketAddr)>,
) -> Result<()> {
    let key = &group.key;

    let heartbeat_schedule = async {
        let group_handle = group_handle.clone();
        let socket = socket.clone();
        let mut notified = notified.clone();

        tokio::spawn(async move {
            let fut = async {
                let mut buff = [0u8; UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + size_of::<Seq>() + size_of::<HeartbeatType>()];
                let mut rng = rand::rngs::SmallRng::from_os_rng();

                loop {
                    let mut list = Vec::new();

                    {
                        let guard = group_handle.mapping.read();

                        for node in guard.values() {
                            let wan = node.node.load().wan_udp_addr;

                            let socket_addr = match wan {
                                None => continue,
                                Some(v) => v
                            };

                            let mut heartbeat_status = node.udp_heartbeat_cache.write();
                            heartbeat_status.check();

                            if node.udp_status.load() != UdpStatus::Unavailable &&
                                heartbeat_status.packet_continuous_loss_count >= packet_loss_limit
                            {
                                node.udp_status.store(UdpStatus::Unavailable);
                            }

                            heartbeat_status.ping();
                            list.push((socket_addr, heartbeat_status.seq));
                        }
                    };

                    for (sock_addr, seq) in list {
                        let len = UdpMsg::heartbeat_encode(key, rng.random(), SERVER_VIRTUAL_ADDR, seq, HeartbeatType::Req, &mut buff);
                        let packet = &mut buff[..len];

                        match UdpMsg::send_msg(&socket, packet, sock_addr).await {
                            Ok(_) => (),
                            Err(UdpSocketErr::FatalError(e)) => return Result::<(), _>::Err(anyhow!(e)),
                            Err(UdpSocketErr::SuppressError(e)) => {
                                warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                            }
                        };
                    }

                    tokio::time::sleep(heartbeat_interval).await;
                }
            };

            tokio::select! {
                res = fut => res,
                _ = notified.changed() => Err(anyhow!("abort task"))
            }
        }).await?
    };

    let recv_handler = async {
        let group_handle = group_handle.clone();
        let socket = socket.clone();
        let mut notified = notified.clone();
        let kcp_acceptor_channel = kcp_acceptor_channel.clone();

        tokio::spawn(async move {
            let fut = async {
                let mut buff = vec![0u8; UDP_BUFF_SIZE];
                let mut rng = rand::rngs::SmallRng::from_os_rng();
                let kcp_sessions = Arc::new(RwLock::new(Vec::<(u32, mpsc::Sender<Bytes>)>::new()));
                let kcp_sessions_expired_list = Arc::new(RwLock::new(HashSet::new()));

                loop {
                    let (len, peer_addr) = match UdpMsg::recv_msg(socket.deref(), &mut buff).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to process UDP message for group {}: {:?}", group.name, e.as_ref());
                            continue;
                        }
                    };

                    let packet = &mut buff[..len];

                    let msg = match UdpMsg::decode(key, packet) {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("Failed to process UDP message for group {}: {:?}", group.name, e);
                            continue;
                        }
                    };

                    match msg {
                        UdpMsg::Heartbeat(dst_virt_addr, seq, HeartbeatType::Req) => {
                            let mut is_known = false;

                            {
                                let guard = group_handle.mapping.read();

                                if let Some(handle) = guard.get(&dst_virt_addr) {
                                    is_known = true;
                                    let node = handle.node.load();

                                    if node.wan_udp_addr != Some(peer_addr) {
                                        let mut new_node = (**node).clone();
                                        drop(node);

                                        new_node.wan_udp_addr = Some(peer_addr);
                                        handle.node.store(Arc::new(new_node));
                                        group_handle.sync(&guard)?;
                                    }
                                }
                            };

                            if is_known {
                                let len = UdpMsg::heartbeat_encode(key, rng.random(), SERVER_VIRTUAL_ADDR, seq, HeartbeatType::Resp, &mut buff);
                                let packet = &mut buff[..len];

                                match UdpMsg::send_msg(&socket, packet, peer_addr).await {
                                    Ok(_) => (),
                                    Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                                    Err(UdpSocketErr::SuppressError(e)) => {
                                        warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                                    }
                                };
                            }
                        }
                        UdpMsg::Heartbeat(dst_virt_addr, seq, HeartbeatType::Resp) => {
                            let guard = group_handle.mapping.read();

                            if let Some(node) = guard.get(&dst_virt_addr) {
                                let mut udp_heartbeat_cache = node.udp_heartbeat_cache.write();

                                if udp_heartbeat_cache.reply(seq).is_none() {
                                    continue;
                                }

                                if node.udp_status.load() == UdpStatus::Unavailable &&
                                    udp_heartbeat_cache.packet_continuous_recv_count >= packet_continuous_recv
                                {
                                    node.udp_status.store(UdpStatus::Available {dst_addr: peer_addr});
                                }
                            }
                        }
                        UdpMsg::Relay(dst_virt_addr, data) => {
                            if !group.allow_udp_relay {
                                continue;
                            }

                            let flow_control_res = group_handle.flow_control.push(dst_virt_addr, data.len() as u64);

                            if flow_control_res == PushResult::Reject {
                                continue;
                            }

                            let mut fut = None;

                            {
                                let guard = group_handle.mapping.read();

                                if let Some(handle) = guard.get(&dst_virt_addr) {
                                    let relay = handle.node.load().mode.relay.clone();

                                    for np in relay {
                                        match np {
                                            NetProtocol::TCP => {
                                                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + data.len());
                                                buff[TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()..].copy_from_slice(data);
                                                TcpMsg::relay_encode(key, rng.random(), dst_virt_addr, data.len(), &mut buff);

                                                match handle.tx.try_send(buff) {
                                                    Ok(_) => {
                                                        if log::max_level() >= log::Level::Debug {
                                                            let f = || {
                                                                let src = get_ip_src_addr(data)?;
                                                                let dst = get_ip_dst_addr(data)?;
                                                                Result::<_, anyhow::Error>::Ok((src, dst))
                                                            };

                                                            if let Ok((src, dst)) = f() {
                                                                debug!("group {} udp handler: tcp message relay to {}; packet {}->{}", group.name, dst_virt_addr, src, dst);
                                                            }
                                                        }
                                                        break;
                                                    }
                                                    Err(e) => warn!("Failed to send packet to TCP channel for group {}: {}", group.name, e)
                                                }
                                            }
                                            NetProtocol::UDP => {
                                                let status = handle.udp_status.load();

                                                let dst_addr = match status {
                                                    UdpStatus::Available { dst_addr } => dst_addr,
                                                    UdpStatus::Unavailable => continue
                                                };

                                                drop(guard);

                                                if log::max_level() >= log::Level::Debug {
                                                    let f = || {
                                                        let src = get_ip_src_addr(data)?;
                                                        let dst = get_ip_dst_addr(data)?;
                                                        Result::<_, anyhow::Error>::Ok((src, dst))
                                                    };

                                                    if let Ok((src, dst)) = f() {
                                                        debug!("group {} udp handler: udp message relay to {}; packet {}->{}", group.name, dst_virt_addr, src, dst);
                                                    }
                                                }

                                                UdpMsg::relay_encode(key, rng.random(), dst_virt_addr, data.len(), packet);
                                                fut = Some(UdpMsg::send_msg(&socket, packet, dst_addr));
                                                break;
                                            }
                                        }
                                    }
                                }
                            };

                            if let Some(fut) = fut {
                                match fut.await {
                                    Ok(_) => (),
                                    Err(UdpSocketErr::FatalError(e)) => return Result::<(), _>::Err(anyhow!(e)),
                                    Err(UdpSocketErr::SuppressError(e)) => {
                                        warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                                    }
                                }
                            }
                        }
                        UdpMsg::KcpData(data) => {
                            let mut send_fut = None;
                            let conv = kcp::get_conv(data);

                            {
                                let kcp_sessions_guard = kcp_sessions.read();
                                let mut kcp_sessions_write_guard;
                                let sessions = &*kcp_sessions_guard;

                                let tx = match sessions.binary_search_by_key(&conv, |(k, _)| *k) {
                                    Ok(i) => {
                                        &sessions[i].1
                                    }
                                    Err(_) => {
                                        drop(kcp_sessions_guard);

                                        {
                                            if kcp_sessions_expired_list.read().contains(&conv) {
                                                continue;
                                            }
                                        }

                                        kcp_sessions_write_guard = kcp_sessions.write();
                                        let sessions = &mut *kcp_sessions_write_guard;

                                        match sessions.binary_search_by_key(&conv, |(k, _)| *k) {
                                            Ok(i) => {
                                                &sessions[i].1
                                            }
                                            Err(i) => {
                                                let kcp_sessions = kcp_sessions.clone();
                                                let (stack_tx, mut stack_rx) = tokio::sync::mpsc::channel(1024);
                                                let socket = socket.clone();
                                                let (handler_kcp_channel, handler_tcp_channel) = tokio::io::duplex(8192);
                                                let kcp_sessions_expired_list = kcp_sessions_expired_list.clone();

                                                tokio::spawn(async move {
                                                    // destruction immediately after the connection is terminated, rather than the entire life cycle
                                                    let block_on = async move {
                                                        let (mut rx, mut tx) = tokio::io::split(handler_tcp_channel);

                                                        let mut stack = KcpStack::new(
                                                            &socket,
                                                            peer_addr,
                                                            conv,
                                                            &mut tx,
                                                            &mut rx,
                                                            &mut stack_rx,
                                                            key,
                                                        );

                                                        stack.block_on().await
                                                    };

                                                    let res = block_on.await;
                                                    kcp_sessions_expired_list.write().insert(conv);

                                                    {
                                                        let mut kcp_sessions_guard = kcp_sessions.write();
                                                        let sessions = &mut *kcp_sessions_guard;
                                                        let remove_index = sessions.binary_search_by_key(&conv, |(k, _)| *k).unwrap();
                                                        sessions.remove(remove_index);
                                                    }

                                                    if let Err(e) = res {
                                                        warn!("KCP transport session failed: {:?}", e);
                                                    }

                                                    tokio::time::sleep(Duration::from_secs(5 * 60)).await;
                                                    kcp_sessions_expired_list.write().remove(&conv);
                                                });
        
                                                send_fut = Some(kcp_acceptor_channel.send((handler_kcp_channel, peer_addr)));
        
                                                sessions.insert(i, (conv, stack_tx));
                                                &sessions[i].1
                                            }
                                        }
                                    }
                                };

                                let mut packet = allocator::alloc(data.len());
                                packet.copy_from_slice(data);
                                let _ = tx.try_send(packet);
                            }

                            if let Some(fut) = send_fut {
                                fut.await?;
                            }
                        }
                        _ => error!("Received invalid UDP message for group {}", group.name),
                    };
                };
            };

            tokio::select! {
                res = fut => res,
                _ = notified.changed() => Err(anyhow!("abort task"))
            }
        }).await?
    };

    tokio::try_join!(heartbeat_schedule, recv_handler)?;
    Ok(())
}

async fn tcp_handler<K: Cipher + Clone + Send + Sync>(
    tcp_listener: TcpListener,
    udp_socket: Arc<UdpSocket>,
    config: &'static ServerConfigFinalize<K>,
    group: &'static GroupFinalize<K>,
    group_handle: Arc<GroupHandle>,
    notified: watch::Receiver<()>,
    mut kcp_acceptor_channel: mpsc::Receiver<(DuplexStream, SocketAddr)>,
) -> Result<()> {
    let nonce_pool = Arc::new(NoncePool::new());
    let address_pool = Arc::new(AddressPool::new(group.address_range)?);

    macro_rules! spawn_task {
        ($stream: expr, $peer_addr: expr) => {{
            let mut tunnel = Tunnel::new(
                $stream,
                udp_socket.clone(),
                config,
                group,
                group_handle.clone(),
                nonce_pool.clone(),
                address_pool.clone(),
            );
    
            let mut notified = notified.clone();
    
            tokio::spawn(async move {
                let res = tokio::select! {
                    res = tunnel.exec() => res,
                    _ = notified.changed() => Err(anyhow!("abort task"))
                };
    
                if let Err(e) = res {
                    match &tunnel.register {
                        None => error!("Tunnel for address {} in group {} failed: {:?}", $peer_addr, group.name, e),
                        Some(v) => error!("Tunnel for node {}({}) in group {} failed: {:?}", v.node_name, v.virtual_addr, group.name, e)
                    }
                }
    
                if let Some(v) = &tunnel.register {
                    warn!("group {} node {}-{} disconnected", group.name, v.node_name, v.virtual_addr);
                }
            });
        }};
    }

    loop {
        tokio::select! {
            res = tcp_listener.accept() => {
                let (stream, peer_addr) = res.context("accept connection error")?;

                stream.set_keepalive()?;
                stream.set_nodelay(true)?;

                let stream = stream.into_split();
                spawn_task!(stream, peer_addr);
            }
            res = kcp_acceptor_channel.recv() => {
                let (stream, peer_addr) = res.ok_or_else(|| anyhow!("kcp channel has been closed"))?;
                let stream = tokio::io::split(stream);
                spawn_task!(stream, peer_addr);
            }
        }
        
    }
}

struct Tunnel<K: 'static, R, W> {
    config: &'static ServerConfigFinalize<K>,
    group: &'static GroupFinalize<K>,
    stream: Option<(R, W)>,
    udp_socket: Arc<UdpSocket>,
    group_handle: Arc<GroupHandle>,
    nonce_pool: Arc<NoncePool>,
    address_pool: Arc<AddressPool>,
    register: Option<Register>,
    bridge: Option<Bridge>,
    node_handle: Option<Arc<NodeHandle>>
}

impl<K, R, W> Tunnel<K, R, W> 
    where 
        K: Cipher + Clone + Send + Sync,
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
{
    fn new(
        stream: (R, W),
        udp_socket: Arc<UdpSocket>,
        config: &'static ServerConfigFinalize<K>,
        group: &'static GroupFinalize<K>,
        group_handle: Arc<GroupHandle>,
        nonce_pool: Arc<NoncePool>,
        address_pool: Arc<AddressPool>,
    ) -> Self {
        Self {
            stream: Some(stream),
            udp_socket,
            config,
            group,
            group_handle,
            nonce_pool,
            address_pool,
            register: None,
            bridge: None,
            node_handle: None
        }
    }

    async fn init(&mut self) -> Result<()> {
        let buff = &mut allocator::alloc(1024);
        let (reader, writer) = self.stream.as_mut().unwrap();
        let key = &self.group.key;
        let mut rng = rand::rngs::SmallRng::from_os_rng();

        loop {
            let nonce_pool = &self.nonce_pool;
            let msg = TcpMsg::read_msg(reader, key, buff).await?
                .ok_or_else(|| anyhow!("node connection closed"))?;

            match msg {
                TcpMsg::GetIdleVirtualAddr => {
                    let addr = self.address_pool.get_idle_addr()
                        .map(|v| (v, self.group.address_range));
                    let len = TcpMsg::get_idle_virtual_addr_res_encode(key, rng.random(), addr, buff)?;
                    TcpMsg::write_msg(writer, &buff[..len]).await?;
                }
                TcpMsg::Register(msg) => {
                    let now = Utc::now().timestamp();
                    let remain = now - msg.register_time;

                    if !(-300..=300).contains(&remain) {
                        let len = TcpMsg::register_res_encode(key, rng.random(), &Err(RegisterError::Timeout), buff)?;
                        TcpMsg::write_msg(writer, &buff[..len]).await?;
                        return Err(anyhow!("register message timeout"));
                    }

                    let not_contained = nonce_pool.set.lock().insert(msg.nonce);

                    if !not_contained {
                        let len = TcpMsg::register_res_encode(key, rng.random(), &Err(RegisterError::NonceRepeat), buff)?;
                        TcpMsg::write_msg(writer, &buff[..len]).await?;
                        return Err(anyhow!("nonce repeat"));
                    }

                    let nonce_pool = nonce_pool.clone();

                    tokio::spawn(async move {
                        time::sleep(Duration::from_secs(300 * 2)).await;
                        nonce_pool.set.lock().remove(&msg.nonce);
                    });

                    if let Err(e) = self.address_pool.allocate(msg.virtual_addr) {
                        let len = TcpMsg::register_res_encode(key, rng.random(), &Err(RegisterError::InvalidVirtualAddress(e)), buff)?;
                        TcpMsg::write_msg(writer, &buff[..len]).await?;
                        return Err(anyhow!(e))
                    };

                    self.register = Some(msg.clone());

                    let node = Node {
                        name: msg.node_name,
                        virtual_addr: msg.virtual_addr,
                        lan_udp_addr: msg.lan_udp_socket_addr,
                        wan_udp_addr: None,
                        mode: msg.proto_mod,
                        allowed_ips: msg.allowed_ips,
                        register_time: msg.register_time,
                        register_nonce: msg.nonce
                    };
                    let (bridge, node_handle) = self.group_handle.join(node)?;
                    self.bridge = Some(bridge);
                    self.node_handle = Some(node_handle);

                    let gc = GroupContent {
                        name: self.group.name.clone(),
                        cidr: self.group.address_range,
                        allow_udp_relay: self.group.allow_udp_relay,
                        allow_tcp_relay: self.group.allow_tcp_relay
                    };

                    let len = TcpMsg::register_res_encode(key, rng.random(), &Ok(gc), buff)?;
                    return TcpMsg::write_msg(writer,  &buff[..len]).await;
                }
                _ => return Err(anyhow!("init message error")),
            }
        }
    }

    async fn exec(&mut self) -> Result<()> {
        self.init().await?;

        info!("Node {} successfully registered via TCP.", self.register.as_ref().unwrap().node_name);

        let (mut bridge, node_handle) = match (self.bridge.take(), &self.node_handle) {
            (Some(bridge), Some(node_handle)) => (bridge, &*node_handle),
            _ => unreachable!(),
        };

        let (rx, mut tx) = self.stream
            .take()
            .unwrap();

        let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);
        let (local_channel_tx, mut local_channel_rx) = mpsc::unbounded_channel();
        let (_notify, notified) = sync::watch::channel(());
        let key = &self.group.key;

        let heartbeat_schedule = async {
            let mut notified = notified.clone();
            let node_handle = node_handle.clone();
            let config = self.config;
            let local_channel_tx = local_channel_tx.clone();
            
            tokio::spawn(async move {
                let fut = async {
                    let mut rng = rand::rngs::SmallRng::from_os_rng();

                    loop {
                        let seq = {
                            let hc = &node_handle.tcp_heartbeat_cache;

                            let mut hc = hc.write();
                            hc.check();

                            if hc.packet_continuous_loss_count >= config.tcp_heartbeat_continuous_loss {
                                return Err(anyhow!("heartbeat receive timeout"))
                            }

                            hc.ping();
                            hc.seq
                        };

                        let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                        TcpMsg::heartbeat_encode(key, rng.random(), seq, HeartbeatType::Req, &mut buff);

                        local_channel_tx.send(buff).map_err(|e| anyhow!("{}", e))?;
                        tokio::time::sleep(config.tcp_heartbeat_interval).await;
                    }
                };

                tokio::select! {
                    res = fut => res,
                    _ = notified.changed() => Err(anyhow!("abort task"))
                }
            }).await?
        };

        let recv_handler = async {
            let mut notified = notified.clone();
            let group_handle = self.group_handle.clone();
            let node_handle = node_handle.clone();
            let udp_socket = self.udp_socket.clone();
            let group = self.group;
            let local_channel_tx = local_channel_tx.clone();

            tokio::spawn(async move {
                let fut = async {
                    let mut buff = vec![0u8; TCP_BUFF_SIZE];
                    let mut rng = rand::rngs::SmallRng::from_os_rng();

                    loop {
                        let sub_buff = &mut buff[UDP_MSG_HEADER_LEN..];
                        let msg = TcpMsg::read_msg(&mut rx, key, sub_buff).await?;

                        let msg = match msg {
                            None => return Ok(()),
                            Some(msg) => msg
                        };

                        match msg {
                            TcpMsg::Relay(dst_virt_addr, packet) => {
                                if !group.allow_tcp_relay {
                                    continue;
                                }

                                let flow_control_res = group_handle.flow_control.push(dst_virt_addr, packet.len() as u64);

                                if flow_control_res == PushResult::Reject {
                                    continue;
                                }

                                let mut fut = None;
                                {
                                    let guard = group_handle.mapping.read();

                                    if let Some(handle) = guard.get(&dst_virt_addr) {
                                        let node = handle.node.load();

                                        for np in &node.mode.relay {
                                            match np {
                                                NetProtocol::TCP => {
                                                    let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + packet.len());
                                                    buff[TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()..].copy_from_slice(packet);
                                                    TcpMsg::relay_encode(key, rng.random(), dst_virt_addr, packet.len(), &mut buff);

                                                    match handle.tx.try_send(buff) {
                                                        Ok(_) => {
                                                            debug!("tcp handler: tcp message relay to node {}", node.name);
                                                            break;
                                                        },
                                                        Err(e) => warn!("Failed to send packet to TCP channel for group {}: {}", group.name, e)
                                                    }
                                                }
                                                NetProtocol::UDP =>  {
                                                    let udp_status = handle.udp_status.load();

                                                    let addr = match udp_status {
                                                        UdpStatus::Available { dst_addr } => dst_addr,
                                                        UdpStatus::Unavailable => continue
                                                    };

                                                    debug!("tcp handler: udp message relay to node {}", node.name);

                                                    drop(node);
                                                    drop(guard);

                                                    let packet_len = packet.len();
                                                    let len = UdpMsg::relay_encode(key, rng.random(), dst_virt_addr, packet_len, &mut buff);

                                                    fut = Some(UdpMsg::send_msg(&udp_socket, &buff[..len], addr));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some(fut) = fut {
                                    match fut.await {
                                        Ok(_) => (),
                                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!(e)),
                                        Err(UdpSocketErr::SuppressError(e)) => {
                                            warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                                        }
                                    }
                                }
                            }
                            TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                                TcpMsg::heartbeat_encode(key, rng.random(), seq, HeartbeatType::Resp, &mut buff);

                                local_channel_tx.send(buff).map_err(|e| anyhow!("{}", e))?;
                            }
                            TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                                node_handle.tcp_heartbeat_cache.write().reply(recv_seq);
                            }
                            TcpMsg::UploadPeers(peers) => {
                                *node_handle.peers_status.write() = Some((peers, Instant::now()));
                            }
                            TcpMsg::FetchPeers => {
                                let mut peers = HashMap::new();
                                let mapping_guard = group_handle.mapping.read();

                                for (&addr, node_handle) in mapping_guard.deref() {
                                    let peers_status = node_handle.peers_status.read();

                                    if let Some((peers_status, update_time)) = peers_status.deref() {
                                        if update_time.elapsed() < Duration::from_secs(10) &&
                                            !peers_status.is_empty()
                                        {
                                            peers.insert(addr, peers_status.clone());
                                        }
                                    }
                                }

                                drop(mapping_guard);

                                let len = TcpMsg::fetch_peers_res_encode(key, rng.random(), &peers, &mut buff)?;
                                let mut data = allocator::alloc(len);
                                data.copy_from_slice(&buff[..len]);
                                local_channel_tx.send(data).map_err(|e| anyhow!("{}", e))?;
                            }
                            _ => return Result::<()>::Err(anyhow!("invalid tcp msg")),
                        }
                    }
                };

                tokio::select! {
                    res = fut => res,
                    _ = notified.changed() => Err(anyhow!("abort task"))
                }
            }).await?
        };

        let send_handler = async {
            let mut notified = notified.clone();

            tokio::spawn(async move {
                let mut buff = vec![0u8; TCP_BUFF_SIZE];
                let mut rng = rand::rngs::SmallRng::from_os_rng();

                loop {
                    tokio::select! {
                        res = bridge.watch_rx.changed() => {
                            if let Err(e) = res {
                                return Result::<(), _>::Err(anyhow!(e));
                            }

                            let node_list: Arc<NodeMap> = bridge.watch_rx.borrow().clone();
                            let len = TcpMsg::node_map_encode(key, rng.random(), &node_list, &mut buff)?;
                            TcpMsg::write_msg(&mut tx, &buff[..len]).await?;
                        }
                        res = bridge.channel_rx.recv() => {
                            let buff = res.ok_or_else(|| anyhow!("channel closed"))?;
                            TcpMsg::write_msg(&mut tx, &buff).await?;
                        }
                        res = local_channel_rx.recv() => {
                            let buff = res.ok_or_else(|| anyhow!("channel closed"))?;
                            TcpMsg::write_msg(&mut tx, &buff).await?;
                        }
                        _ = notified.changed() => return Err(anyhow!("abort task"))
                    }
                }
            }).await?
        };

        // A single task ends normally
        tokio::select! {
            res = heartbeat_schedule => res,
            res = recv_handler => res,
            res = send_handler => res,
        }
    }
}

impl<T, R, W> Drop for Tunnel<T, R, W> {
    fn drop(&mut self) {
        if let Some(reg) = &self.register {
            {
                let mut guard = self.group_handle.mapping.write();

                if guard.remove(&reg.virtual_addr).is_some() {
                    self.group_handle.sync(&guard).expect("failed to sync nodemap");
                }
            }

            self.group_handle.flow_control.remove_address(&reg.virtual_addr);
            self.address_pool.inner.lock().release(&reg.virtual_addr)
        }
    }
}

struct AddressPoolInner {
    used: HashSet<Ipv4Addr>,
    cidr: Ipv4Net,
}

impl AddressPoolInner {
    fn new(cidr: Ipv4Net) -> Result<Self> {
        let pool = AddressPoolInner {
            used: HashSet::new(),
            cidr,
        };
        Ok(pool)
    }

    fn get_idle_addr(&mut self) -> Option<Ipv4Addr> {
        self.cidr
            .hosts()
            .find(|&v| !self.used.contains(&v))
    }

    fn release(&mut self, addr: &Ipv4Addr) {
        self.used.remove(addr);
    }
}

struct AddressPool {
    inner: Arc<Mutex<AddressPoolInner>>,
}

impl AddressPool {
    fn new(address_range: Ipv4Net) -> Result<Self> {
        let pool = AddressPool {
            inner: Arc::new(Mutex::new(AddressPoolInner::new(address_range)?)),
        };
        Ok(pool)
    }

    fn get_idle_addr(&self) -> Option<Ipv4Addr> {
        let addr = self.inner.lock().get_idle_addr()?;
        Some(addr)
    }

    fn allocate(&self, ip: Ipv4Addr) -> Result<(), AllocateError> {
        let mut guard = self.inner.lock();

        if !guard.cidr.contains(&ip) {
            return Err(AllocateError::IpNotBelongNetworkRange);
        }

        if guard.cidr.network() == ip {
            return Err(AllocateError::IpSameAsNetworkAddress);
        }

        if guard.cidr.broadcast() == ip {
            return Err(AllocateError::IpSameAsBroadcastAddress);
        }

        if guard.used.contains(&ip) {
            return Err(AllocateError::IpAlreadyInUse);
        }

        guard.used.insert(ip);
        Ok(())
    }
}

struct NoncePool {
    set: Mutex<HashSet<u32>>,
}

impl NoncePool {
    fn new() -> Self {
        Self {
            set: Mutex::new(HashSet::new()),
        }
    }
}

pub async fn start<K>(config: ServerConfigFinalize<K>) -> Result<()>
    where
        K: Cipher + Clone + Send + Sync + 'static
{
    let config = &*Box::leak(Box::new(config));
    let mut futures = Vec::with_capacity(config.groups.len());
    let mut group_handles = Vec::with_capacity(config.groups.len());

    for group in &config.groups {
        let gh = Arc::new(GroupHandle::new(config.channel_limit, group));
        group_handles.push(gh.clone());

        let fut = async {
            let listen_addr = group.listen_addr;

            let udp_socket = UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("udp socket bind {} error", listen_addr))?;

            let udp_socket = Arc::new(udp_socket);

            info!("UDP socket for group {} is listening on {}", group.name, listen_addr);

            let tcp_listener = TcpListener::bind(listen_addr)
                .await
                .with_context(|| format!("tcp socket bind {} error", listen_addr))?;

            info!("TCP listener for group {} is listening on {}", group.name, listen_addr);

            let (_notify, notified) = watch::channel(());
            let gh1 = gh.clone();

            let (kcp_acceptor_channel_tx, kcp_acceptor_channel_rx) = tokio::sync::mpsc::channel(1024);

            let udp_handle = async {
                let fut = udp_handler(
                    group,
                    udp_socket.clone(),
                    gh1,
                    config.udp_heartbeat_interval,
                    config.udp_heartbeat_continuous_loss,
                    config.udp_heartbeat_continuous_recv,
                    notified.clone(),
                    kcp_acceptor_channel_tx,
                );

                fut.await.context("udp handler error")
            };

            let tcp_handle = async {
                let mut notified = notified.clone();

                let fut = tcp_handler(
                    tcp_listener,
                    udp_socket.clone(),
                    config,
                    group,
                    gh,
                    notified.clone(),
                    kcp_acceptor_channel_rx,
                );

                tokio::spawn(async move {
                    tokio::select! {
                        res = fut => res,
                        _ = notified.changed() => Err(anyhow!("abort task"))
                    }
                })
                .await?
                .context("tcp handler error")
            };

            tokio::try_join!(udp_handle, tcp_handle).map(|_| ())
        };

        futures.push(async {
            info!("Starting server for group {}...", group.name);

            if let Err(e) = fut.await {
                error!("Server for group {} failed: {:?}", group.name, e)
            }
        });
    }

    let handle = async {
        futures_util::future::join_all(futures).await;
        Ok(())
    };

    let api_handle = api_start(config.api_addr, group_handles);
    tokio::try_join!(handle, api_handle)?;
    Ok(())
}

pub async fn info(api_addr: &str) -> Result<()> {
    let mut info_app = App::new(api_addr.to_string());
    let mut terminal = ratatui::init();
    let res = info_app.run(&mut terminal).await;
    ratatui::restore();
    res
}