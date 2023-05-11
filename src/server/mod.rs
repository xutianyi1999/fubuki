use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use chrono::Utc;
use hyper::{Body, Method, Request};
use hyper::body::Buf;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use prettytable::{row, Table};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, watch};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time;

use crate::{GroupFinalize, ServerInfoType};
use crate::common::{allocator, utc_to_str};
use crate::common::allocator::Bytes;
use crate::common::cipher::Cipher;
use crate::common::net::{get_ip_dst_addr, get_ip_src_addr, HeartbeatCache, HeartbeatInfo, SocketExt, UdpStatus};
use crate::common::net::protocol::{AllocateError, GroupContent, HeartbeatType, NetProtocol, Node, Register, RegisterError, Seq, SERVER_VIRTUAL_ADDR, TCP_BUFF_SIZE, TCP_MSG_HEADER_LEN, TcpMsg, UDP_BUFF_SIZE, UDP_MSP_HEADER_LEN, UdpMsg, VirtualAddr};
use crate::server::api::api_start;
use crate::ServerConfigFinalize;

mod api;

pub type NodeMap = HashMap<VirtualAddr, Node>;

struct NodeHandle {
    node: ArcSwap<Node>,
    udp_status: ArcSwap<UdpStatus>,
    udp_heartbeat_cache: RwLock<HeartbeatCache>,
    tcp_heartbeat_cache: RwLock<HeartbeatCache>,
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
            udp_status: **value.udp_status.load(),
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
    mapping: RwLock<HashMap<VirtualAddr, NodeHandle>>,
    watch: (watch::Sender<Arc<NodeMap>>, watch::Receiver<Arc<NodeMap>>),
}

impl GroupHandle {
    fn new<K>(
        channel_limit: usize,
        group_config: &GroupFinalize<K>
    ) -> Self {
        GroupHandle {
            name: group_config.name.clone(),
            listen_addr: group_config.listen_addr,
            address_range: group_config.address_range,
            limit: channel_limit,
            mapping: RwLock::new(HashMap::new()),
            watch: watch::channel(Arc::new(HashMap::new())),
        }
    }

    fn join(&self, node: Node) -> Result<Bridge> {
        let (_, watch_rx) = &self.watch;
        let (tx, rx) = mpsc::channel(self.limit);

        let mut mp_guard = self.mapping.write();

        mp_guard.insert(
            node.virtual_addr,
            NodeHandle {
                node: ArcSwap::from_pointee(node),
                tx,
                udp_status: ArcSwap::from_pointee(UdpStatus::Unavailable),
                udp_heartbeat_cache: RwLock::new(HeartbeatCache::new()),
                tcp_heartbeat_cache: RwLock::new(HeartbeatCache::new())
            },
        );
        self.sync(&mp_guard)?;

        let bridge = Bridge {
            channel_rx: rx,
            watch_rx: watch_rx.clone(),
        };
        Ok(bridge)
    }

    fn sync(&self, node_map: &HashMap<VirtualAddr, NodeHandle>) -> Result<()> {
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
                    .map(|(k, v)| (*k, NodeInfo::from(v)))
                    .collect()
            }
        }
    }
}

async fn udp_handler<K: Cipher>(
    group: &'static GroupFinalize<K>,
    socket: Arc<UdpSocket>,
    key: K,
    group_handle: Arc<GroupHandle>,
    heartbeat_interval: Duration,
    packet_loss_limit: u64,
    packet_continuous_recv: u64,
) -> Result<()> {
    let heartbeat_schedule = async {
        let mut buff = [0u8; UDP_MSP_HEADER_LEN + size_of::<VirtualAddr>() + size_of::<Seq>() + size_of::<HeartbeatType>()];

        loop {
            let mut list = Vec::new();

            {
                let guard = group_handle.mapping.read();

                for node in guard.values() {
                    let socket_addr = match node.node.load().wan_udp_addr {
                        None => continue,
                        Some(v) => v
                    };

                    let mut heartbeat_status = node.udp_heartbeat_cache.write();
                    heartbeat_status.check();

                    if **node.udp_status.load() != UdpStatus::Unavailable &&
                        heartbeat_status.packet_continuous_loss_count >= packet_loss_limit
                    {
                        node.udp_status.store(Arc::new(UdpStatus::Unavailable));
                    }

                    heartbeat_status.request();
                    list.push((socket_addr, heartbeat_status.seq));
                }
            };

            for (sock_addr, seq) in list {
                let len = UdpMsg::heartbeat_encode(SERVER_VIRTUAL_ADDR, seq, HeartbeatType::Req, &mut buff);
                let packet = &mut buff[..len];
                key.encrypt(packet, 0);
                let res = socket.send_to(packet, sock_addr).await;

                if let Err(e) = res {
                    return Result::<(), _>::Err(anyhow!(e));
                }
            }

            tokio::time::sleep(heartbeat_interval).await;
        }
    };

    let recv_handler = async {
        let mut buff = vec![0u8; UDP_BUFF_SIZE];

        loop {
            let (len, peer_addr) = match socket.recv_from(&mut buff).await {
                Ok(v) => v,
                Err(e) => {
                    error!("group {} receive udp message error: {:?}", group.name, e);
                    continue;
                }
            };

            let packet = &mut buff[..len];
            key.decrypt(packet, 0);

            let msg = match UdpMsg::decode(packet) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("group {} receive udp message error: {:?}", group.name, e);
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
                                new_node.wan_udp_addr = Some(peer_addr);
                                drop(node);
                                handle.node.store(Arc::new(new_node));
                                group_handle.sync(&guard)?;
                            }
                        }
                    };

                    if is_known {
                        let len = UdpMsg::heartbeat_encode(SERVER_VIRTUAL_ADDR, seq, HeartbeatType::Resp, &mut buff);
                        let packet = &mut buff[..len];
                        key.encrypt(packet, 0);
                        socket.send_to(packet, peer_addr).await?;
                    }
                }
                UdpMsg::Heartbeat(dst_virt_addr, seq, HeartbeatType::Resp) => {
                    let guard = group_handle.mapping.read();

                    if let Some(node) = guard.get(&dst_virt_addr) {
                        let mut udp_heartbeat_cache = node.udp_heartbeat_cache.write();

                        if udp_heartbeat_cache.response(seq).is_none() {
                            continue;
                        }

                        if **node.udp_status.load() == UdpStatus::Unavailable &&
                            udp_heartbeat_cache.packet_continuous_recv_count >= packet_continuous_recv
                        {
                            node.udp_status.store(Arc::new(UdpStatus::Available {dst_addr: peer_addr}));
                        }
                    }
                }
                UdpMsg::Relay(dst_virt_addr, data) => {
                    let mut fut = None;

                    {
                        let guard = group_handle.mapping.read();

                        if let Some(handle) = guard.get(&dst_virt_addr) {
                            for np in handle.node.load().mode.relay.clone() {
                                match np {
                                    NetProtocol::TCP => {
                                        let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + data.len());
                                        TcpMsg::relay_encode(dst_virt_addr, data.len(), &mut buff);
                                        buff[TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()..].copy_from_slice(data);

                                        match handle.tx.try_send(buff) {
                                            Ok(_) => {
                                                if log::max_level() >= log::Level::Debug {
                                                    let f = || {
                                                        let src = get_ip_src_addr(packet)?;
                                                        let dst = get_ip_dst_addr(packet)?;
                                                        Result::<_, anyhow::Error>::Ok((src, dst))
                                                    };

                                                    if let Ok((src, dst)) = f() {
                                                        debug!("group {} udp handler: tcp message relay to {}; packet {}->{}", group.name, dst_virt_addr, src, dst);
                                                    }
                                                }
                                                break;
                                            }
                                            Err(e) => warn!("group {} send packet to tcp channel error: {}", group.name, e)
                                        }
                                    }
                                    NetProtocol::UDP => {
                                        let dst_addr = match **handle.udp_status.load() {
                                            UdpStatus::Available { dst_addr } => dst_addr,
                                            UdpStatus::Unavailable => continue
                                        };

                                        if log::max_level() >= log::Level::Debug {
                                            let f = || {
                                                let src = get_ip_src_addr(packet)?;
                                                let dst = get_ip_dst_addr(packet)?;
                                                Result::<_, anyhow::Error>::Ok((src, dst))
                                            };

                                            if let Ok((src, dst)) = f() {
                                                debug!("group {} udp handler: tcp message relay to {}; packet {}->{}", group.name, dst_virt_addr, src, dst);
                                            }
                                        }

                                        key.encrypt(packet, 0);
                                        fut = Some(socket.send_to(packet, dst_addr));
                                        break;
                                    }
                                }
                            }
                        }
                    };

                    if let Some(fut) = fut {
                        if let Err(e) = fut.await {
                            return Result::<(), _>::Err(anyhow!(e));
                        }
                    }
                }
                _ => error!("group {} receive invalid udp message", group.name),
            };
        };
    };

    tokio::try_join!(heartbeat_schedule, recv_handler)?;
    Ok(())
}

async fn tcp_handler<K: Cipher + Clone + Send + Sync + 'static>(
    tcp_listener: TcpListener,
    udp_socket: Arc<UdpSocket>,
    config: &'static ServerConfigFinalize<K>,
    group: &'static GroupFinalize<K>,
    group_handle: Arc<GroupHandle>,
) -> Result<()> {
    let nonce_pool = Arc::new(NoncePool::new());
    let address_pool = Arc::new(AddressPool::new(group.address_range)?);

    loop {
        let (stream, peer_addr) = tcp_listener
            .accept()
            .await
            .context("accept connection error")?;

        let mut tunnel = Tunnel::new(
            stream,
            udp_socket.clone(),
            config,
            group,
            group_handle.clone(),
            nonce_pool.clone(),
            address_pool.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) = tunnel.exec().await {
                match &tunnel.register {
                    None => error!("group {} address {} tunnel error: {:?}", group.name, peer_addr, e),
                    Some(v) => error!("group {} node {}-{} tunnel error: {:?}", group.name, v.node_name, v.virtual_addr, e)
                }
            }

            if let Some(v) = &tunnel.register {
                warn!("group {} node {}-{} disconnected", group.name, v.node_name, v.virtual_addr);
            }
        });
    }
}

struct Tunnel<K: 'static> {
    config: &'static ServerConfigFinalize<K>,
    group: &'static GroupFinalize<K>,
    stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    group_handle: Arc<GroupHandle>,
    nonce_pool: Arc<NoncePool>,
    address_pool: Arc<AddressPool>,
    register: Option<Register>,
    bridge: Option<Bridge>,
}

impl<K: Cipher> Tunnel<K> {
    fn new(
        stream: TcpStream,
        udp_socket: Arc<UdpSocket>,
        config: &'static ServerConfigFinalize<K>,
        group: &'static GroupFinalize<K>,
        group_handle: Arc<GroupHandle>,
        nonce_pool: Arc<NoncePool>,
        address_pool: Arc<AddressPool>,
    ) -> Self {
        Self {
            stream,
            udp_socket,
            config,
            group,
            group_handle,
            nonce_pool,
            address_pool,
            register: None,
            bridge: None,
        }
    }

    async fn init(&mut self) -> Result<()> {
        let buff = &mut allocator::alloc(1024);
        let stream = &mut self.stream;
        let key = &self.group.key;

        loop {
            let nonce_pool = &self.nonce_pool;
            let msg = TcpMsg::read_msg(stream, key, buff).await?
                .ok_or_else(|| anyhow!("node connection closed"))?;

            match msg {
                TcpMsg::GetIdleVirtualAddr => {
                    let addr = self.address_pool.get_idle_addr()
                        .map(|v| (v, self.group.address_range));
                    let len = TcpMsg::get_idle_virtual_addr_res_encode(addr, buff)?;
                    TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;
                }
                TcpMsg::Register(msg) => {
                    let now = Utc::now().timestamp();
                    let remain = now - msg.register_time;

                    if !(-10..=10).contains(&remain) {
                        let len = TcpMsg::register_res_encode(&Err(RegisterError::Timeout), buff)?;
                        TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;
                        return Err(anyhow!("register message timeout"));
                    }

                    let res = {
                        let mut guard = nonce_pool.set.lock();

                        if !guard.contains(&msg.nonce) {
                            guard.insert(msg.nonce);
                            true
                        } else {
                            false
                        }
                    };

                    if !res {
                        let len = TcpMsg::register_res_encode(&Err(RegisterError::NonceRepeat), buff)?;
                        TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;
                        return Err(anyhow!("nonce repeat"));
                    }

                    let nonce_pool = nonce_pool.clone();

                    tokio::spawn(async move {
                        time::sleep(Duration::from_secs(60)).await;
                        nonce_pool.set.lock().remove(&msg.nonce);
                    });

                    if let Err(e) = self.address_pool.allocate(msg.virtual_addr) {
                        let len = TcpMsg::register_res_encode(&Err(RegisterError::InvalidVirtualAddress(e)), buff)?;
                        TcpMsg::write_msg(stream, key, &mut buff[..len]).await?;
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
                    let bridge = self.group_handle.join(node)?;
                    self.bridge = Some(bridge);

                    let gc = GroupContent {
                        name: self.group.name.clone(),
                        cidr: self.group.address_range
                    };

                    let len = TcpMsg::register_res_encode(&Ok(gc), buff)?;
                    return TcpMsg::write_msg(stream, key, &mut buff[..len]).await;
                }
                _ => return Err(anyhow!("init message error")),
            }
        }
    }

    async fn exec(&mut self) -> Result<()> {
        self.stream.set_keepalive()?;
        self.init().await?;

        info!("tcp handler: node {} is registered", self.register.as_ref().unwrap().node_name);

        let (bridge, virtual_addr) = match (&mut self.bridge, &self.register) {
            (Some(bridge), Some(reg)) => (bridge, reg.virtual_addr),
            _ => unreachable!(),
        };

        let (mut rx, mut tx) = self.stream.split();
        let key = &self.group.key;

        let (local_channel_tx, mut local_channel_rx) = mpsc::unbounded_channel();

        let heartbeat_schedule = async {
            loop {
                let seq = {
                    let guard = self.group_handle.mapping.read();

                    let hc = match guard.get(&virtual_addr) {
                        None => return Result::<(), _>::Err(anyhow!("can't get current environment node")),
                        Some(node) => &node.tcp_heartbeat_cache
                    };

                    let mut hc = hc.write();
                    hc.check();

                    if hc.packet_continuous_loss_count >= self.config.tcp_heartbeat_continuous_loss {
                        return Err(anyhow!("heartbeat receive timeout"))
                    }

                    hc.request();
                    hc.seq
                };

                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                TcpMsg::heartbeat_encode(seq, HeartbeatType::Req, &mut buff);

                local_channel_tx.send(buff).map_err(|e| anyhow!("{}", e))?;
                tokio::time::sleep(self.config.tcp_heartbeat_interval).await;
            }
        };

        let recv_handler = async {
            let mut buff = vec![0u8; TCP_BUFF_SIZE];

            loop {
                let sub_buff = &mut buff[UDP_MSP_HEADER_LEN..];
                let msg = TcpMsg::read_msg(&mut rx, key, sub_buff).await?;

                let msg = match msg {
                    None => return Ok(()),
                    Some(msg) => msg
                };

                match msg {
                    TcpMsg::Relay(dst_virt_addr, packet) => {
                        let mut fut = None;
                        {
                            let guard = self.group_handle.mapping.read();

                            if let Some(handle) = guard.get(&dst_virt_addr) {
                                let node = handle.node.load();

                                for np in &node.mode.relay {
                                    match np {
                                        NetProtocol::TCP => {
                                            let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + packet.len());
                                            TcpMsg::relay_encode(dst_virt_addr, packet.len(), &mut buff);
                                            buff[TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()..].copy_from_slice(packet);

                                            match handle.tx.try_send(buff) {
                                                Ok(_) => {
                                                    debug!("tcp handler: tcp message relay to node {}", node.name);
                                                    break;
                                                },
                                                Err(e) => warn!("group {} send packet to tcp channel error: {}", self.group.name, e)
                                            }
                                        }
                                        NetProtocol::UDP =>  {
                                            let addr = match **handle.udp_status.load() {
                                                UdpStatus::Available { dst_addr } => dst_addr,
                                                UdpStatus::Unavailable => continue
                                            };

                                            debug!("tcp handler: udp message relay to node {}", node.name);

                                            let packet_len = packet.len();
                                            let len = UdpMsg::relay_encode(dst_virt_addr, packet_len, &mut buff);
                                            key.encrypt(&mut buff[..len], 0);

                                            fut = Some(self.udp_socket.send_to(&buff[..len], addr));
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(fut) = fut {
                            fut.await?;
                        }
                    }
                    TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                        let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                        TcpMsg::heartbeat_encode(seq, HeartbeatType::Resp, &mut buff);

                        local_channel_tx.send(buff).map_err(|e| anyhow!("{}", e))?;
                    }
                    TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                        match self.group_handle.mapping.read().get(&virtual_addr) {
                            None => return Err(anyhow!("can't get current environment node")),
                            Some(node) => node.tcp_heartbeat_cache.write().response(recv_seq)
                        };
                    }
                    _ => return Result::<()>::Err(anyhow!("invalid tcp msg")),
                }
            }
        };

        let send_handler = async {
            let mut buff = vec![0u8; TCP_BUFF_SIZE];

            loop {
                tokio::select! {
                    res = bridge.watch_rx.changed() => {
                        if let Err(e) = res {
                            return Result::<(), _>::Err(anyhow!(e));
                        }

                        let node_list: Arc<NodeMap> = bridge.watch_rx.borrow().clone();
                        let len = TcpMsg::node_map_encode(&node_list, &mut buff)?;
                        TcpMsg::write_msg(&mut tx, key, &mut buff[..len]).await?;
                    }
                    res = bridge.channel_rx.recv() => {
                        let mut buff = res.ok_or_else(|| anyhow!("channel closed"))?;
                        TcpMsg::write_msg(&mut tx, key, &mut buff).await?;
                    }
                    res = local_channel_rx.recv() => {
                        let mut buff = res.ok_or_else(|| anyhow!("channel closed"))?;
                        TcpMsg::write_msg(&mut tx, key, &mut buff).await?;
                    }
                }
            }
        };

        tokio::select! {
            res = heartbeat_schedule => res?,
            res = recv_handler => res?,
            res = send_handler => res?
        }

        Ok(())
    }
}

impl<T> Drop for Tunnel<T> {
    fn drop(&mut self) {
        if let Some(reg) = &self.register {
            {
                let mut guard = self.group_handle.mapping.write();

                if guard.remove(&reg.virtual_addr).is_some() {
                    self.group_handle.sync(&guard).expect("sync node mapping failure");
                }
            }

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

pub(crate) async fn start<K>(config: ServerConfigFinalize<K>) -> Result<()>
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
            let key = group.key.clone();
            let listen_addr = group.listen_addr;

            let udp_socket = UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("udp socket bind {} error", listen_addr))?;

            let udp_socket = Arc::new(udp_socket);

            info!("group {} udp socket listening on {}", group.name, listen_addr);

            let tcp_listener = TcpListener::bind(listen_addr)
                .await
                .with_context(|| format!("tcp socket bind {} error", listen_addr))?;

            info!("group {} tcp socket listening on {}", group.name, listen_addr);

            let notify = Arc::new(Notify::new());
            let gh1 = gh.clone();

            let udp_handle = async {
                let notify = notify.clone();
                let fut = udp_handler(
                    group,
                    udp_socket.clone(),
                    key,
                    gh1,
                    config.udp_heartbeat_interval,
                    config.udp_heartbeat_continuous_loss,
                    config.udp_heartbeat_continuous_recv
                );

                tokio::spawn(async move {
                    tokio::select! {
                        res = fut => res,
                        _ = notify.notified() => Ok(())
                    }
                })
                .await?
                .context("udp handler error")
            };

            let tcp_handle = async {
                let notify = notify.clone();
                let fut = tcp_handler(
                    tcp_listener,
                    udp_socket.clone(),
                    config,
                    group,
                    gh,
                );

                tokio::spawn(async move {
                    tokio::select! {
                        res = fut => res,
                        _ = notify.notified() => Ok(())
                    }
                })
                .await?
                .context("tcp handler error")
            };

            let res = tokio::try_join!(udp_handle, tcp_handle).map(|_| ());
            notify.notify_waiters();
            res
        };

        futures.push(async {
            info!("group {} server start", group.name);

            if let Err(e) = fut.await {
                error!("group {} server error: {:?}", group.name, e)
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

pub(crate) async fn info(api_addr: &str, info_type: ServerInfoType) -> Result<()> {
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
    let groups: Vec<GroupInfo> = serde_json::from_reader(body.reader())?;

    let mut table = Table::new();

    match info_type {
        ServerInfoType::Group => {
            table.add_row(row!["NAME", "LISTENING_ADDRESS", "ADDRESS_RANGE"]);

            for group in groups {
                table.add_row(row![
                    group.name,
                    group.listen_addr,
                    group.address_range
                ]);
            }
        }
        ServerInfoType::NodeMap { group_name, node_ip: None } => {
            table.add_row(row!["NAME", "IP", "REGISTER_TIME"]);

            for group in groups {
                if group.name == group_name {
                    for node in group.node_map.values() {
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
        ServerInfoType::NodeMap { group_name, node_ip: Some(ip) } => {
            for group in groups {
                if group.name == group_name {
                    if let Some(node) = group.node_map.get(&ip) {
                        let register_time = utc_to_str(node.node.register_time)?;

                        table.add_row(row!["NAME", node.node.name]);
                        table.add_row(row!["IP", node.node.virtual_addr]);
                        table.add_row(row!["LAN_ADDRESS", format!("{:?}", node.node.lan_udp_addr)]);
                        table.add_row(row!["WAN_ADDRESS", format!("{:?}", node.node.wan_udp_addr)]);
                        table.add_row(row!["PROTOCOL_MODE",  format!("{:?}", node.node.mode)]);
                        table.add_row(row!["ALLOWED_IPS",  format!("{:?}", node.node.allowed_ips)]);
                        table.add_row(row!["REGISTER_TIME", register_time]);
                        table.add_row(row!["UDP_STATUS", node.udp_status]);
                        table.add_row(row!["UDP_LATENCY", format!("{:?}", node.udp_heartbeat_cache.elapsed)]);
                        table.add_row(row!["UDP_LOSS_RATE", format!("{}%", node.udp_heartbeat_cache.packet_loss_count as f32 / node.udp_heartbeat_cache.send_count as f32 * 100f32)]);
                        table.add_row(row!["TCP_LATENCY", format!("{:?}", node.tcp_heartbeat_cache.elapsed)]);
                        table.add_row(row!["TCP_LOSS_RATE", format!("{}%", node.tcp_heartbeat_cache.packet_loss_count as f32 / node.tcp_heartbeat_cache.send_count as f32 * 100f32)]);
                    }
                    break;
                }
            }
        }
    }

    table.printstd();
    Ok(())
}