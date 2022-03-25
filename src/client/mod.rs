use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use anyhow::{anyhow, Context};
use chrono::Utc;
use futures_util::FutureExt;
use parking_lot::RwLock;
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{unbounded_channel, Receiver, Sender};
use tokio::time;

pub use api::{call, Req};

use crate::client::api::api_start;
use crate::common::cipher::Aes128Ctr;
use crate::common::net::msg_operator::{TcpMsgReader, TcpMsgWriter, TCP_BUFF_SIZE, UDP_BUFF_SIZE};
use crate::common::net::proto::{HeartbeatType, MsgResult, Node, NodeId, TcpMsg, UdpMsg};
use crate::common::net::{proto, SocketExt};
use crate::common::{HashMap, HashSet, MapInit, SetInit};
use crate::tun::create_device;
use crate::tun::TunDevice;
use crate::{ClientConfigFinalize, NetworkRangeFinalize, TunIpAddr};

mod api;

static mut LOCAL_NODE_ID: NodeId = 0;
static mut CONFIG: MaybeUninit<ClientConfigFinalize> = MaybeUninit::uninit();
static mut INTERFACE_MAP: MaybeUninit<InterfaceMap> = MaybeUninit::uninit();
static mut DIRECT_NODE_LIST: MaybeUninit<DirectNodeList> = MaybeUninit::uninit();

fn set_local_node_id(id: NodeId) {
    unsafe { LOCAL_NODE_ID = id }
}

fn set_config(config: ClientConfigFinalize) {
    unsafe { CONFIG.write(config) };
}

fn set_interface_map(map: InterfaceMap) {
    unsafe { INTERFACE_MAP.write(map) };
}

fn set_direct_node_list(list: DirectNodeList) {
    unsafe { DIRECT_NODE_LIST.write(list) };
}

fn get_local_node_id() -> NodeId {
    unsafe { LOCAL_NODE_ID }
}

fn get_config() -> &'static ClientConfigFinalize {
    unsafe { CONFIG.assume_init_ref() }
}

fn get_interface_map() -> &'static InterfaceMap {
    unsafe { INTERFACE_MAP.assume_init_ref() }
}

fn get_direct_node_list() -> &'static DirectNodeList {
    unsafe { DIRECT_NODE_LIST.assume_init_ref() }
}

struct InterfaceInfo<Map> {
    node_map: Map,
    server_addr: String,
    tcp_handler_channel: Option<Sender<(Box<[u8]>, NodeId)>>,
    udp_socket: Option<Arc<UdpSocket>>,
    key: Aes128Ctr,
    try_send_to_lan_addr: bool,
}

struct InterfaceMap {
    // local_addr -> (tun_addr -> node)
    map: HashMap<Ipv4Addr, InterfaceInfo<RwLock<Arc<HashMap<Ipv4Addr, Node>>>>>,
    version: AtomicU8,
}

impl InterfaceMap {
    fn new(map: HashMap<Ipv4Addr, InterfaceInfo<()>>) -> Self {
        let map = map
            .into_iter()
            .map(|(tun_addr, info)| {
                let network_segment = InterfaceInfo {
                    server_addr: info.server_addr,
                    node_map: RwLock::new(Arc::new(HashMap::new())),
                    tcp_handler_channel: info.tcp_handler_channel,
                    udp_socket: info.udp_socket,
                    key: info.key,
                    try_send_to_lan_addr: info.try_send_to_lan_addr,
                };
                (tun_addr, network_segment)
            })
            .collect();

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

        if let Some(info) = self.map.get(local_tun_addr) {
            *info.node_map.write() = map;
            self.version.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn try_load(&self) -> Option<HashMap<Ipv4Addr, InterfaceInfo<Arc<HashMap<Ipv4Addr, Node>>>>> {
        let mut map = HashMap::with_capacity(self.map.len());

        for (k, node_map) in &self.map {
            let range = InterfaceInfo {
                server_addr: node_map.server_addr.clone(),
                node_map: node_map.node_map.try_read()?.clone(),
                tcp_handler_channel: node_map.tcp_handler_channel.clone(),
                udp_socket: node_map.udp_socket.clone(),
                key: node_map.key.clone(),
                try_send_to_lan_addr: node_map.try_send_to_lan_addr,
            };
            map.insert(*k, range);
        }
        Some(map)
    }

    fn load(&self) -> HashMap<Ipv4Addr, InterfaceInfo<Arc<HashMap<Ipv4Addr, Node>>>> {
        let mut map = HashMap::with_capacity(self.map.len());

        for (k, node_map) in &self.map {
            let range = InterfaceInfo {
                server_addr: node_map.server_addr.clone(),
                node_map: node_map.node_map.read().clone(),
                tcp_handler_channel: node_map.tcp_handler_channel.clone(),
                udp_socket: node_map.udp_socket.clone(),
                key: node_map.key.clone(),
                try_send_to_lan_addr: node_map.try_send_to_lan_addr,
            };
            map.insert(*k, range);
        }
        map
    }
}

macro_rules! init_interface_map {
    () => {
        let mut local_interface_map: HashMap<
            Ipv4Addr,
            InterfaceInfo<Arc<HashMap<Ipv4Addr, Node>>>,
        > = HashMap::new();
        let mut local_interface_map_version = 0;

        macro_rules! get_local_interface_map {
            () => {{
                let interface_map = get_interface_map();
                let interface_map_version = interface_map.version();

                if local_interface_map_version != interface_map_version {
                    if let Some(v) = interface_map.try_load() {
                        local_interface_map = v;
                        local_interface_map_version = interface_map_version;
                    }
                }
                &local_interface_map
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
            list: RwLock::new(HashMap::new()),
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn try_load(&self) -> Option<HashSet<NodeId>> {
        let guard = self.list.try_read()?;
        let set: HashSet<NodeId> = guard.keys().copied().collect();
        Some(set)
    }

    fn load(&self) -> HashSet<NodeId> {
        let guard = self.list.read();
        guard.keys().copied().collect()
    }

    fn try_update(&self, node_id: NodeId) {
        let now = Utc::now().timestamp();

        {
            let guard = match self.list.try_read() {
                Some(guard) => guard,
                None => return,
            };

            if let Some(time) = guard.get(&node_id) {
                time.store(now, Ordering::Relaxed);
                return;
            }
        }

        let option = {
            let mut guard = match self.list.try_write() {
                Some(guard) => guard,
                None => return,
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
            None => return,
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
    };
}

fn tun_handler<T: TunDevice>(tun: &T) -> Result<()> {
    // TODO need to be optimized
    let mut buff = vec![0u8; UDP_BUFF_SIZE];
    let buff = (&mut buff[..]) as *mut [u8];

    init_interface_map!();
    init_local_direct_node_list!();

    loop {
        let data = match tun
            .recv_packet(unsafe { &mut (&mut *buff)[2..] })
            .context("Read packet from tun error")?
        {
            0 => continue,
            len => unsafe { &(&*buff)[2..len + 2] },
        };

        let src_addr = proto::get_ip_src_addr(data)?;
        let dst_addr = proto::get_ip_dst_addr(data)?;

        let interface_map: &HashMap<Ipv4Addr, InterfaceInfo<Arc<HashMap<Ipv4Addr, Node>>>> =
            get_local_interface_map!();

        let interface_info = match interface_map.get(&src_addr) {
            Some(v) => v,
            None => continue,
        };

        let (local_node, dst_node) = match (
            interface_info.node_map.get(&src_addr),
            interface_info.node_map.get(&dst_addr),
        ) {
            (Some(v1), Some(v2)) => (v1, v2),
            _ => continue,
        };

        if local_node.mode.udp_support() && dst_node.mode.udp_support() {
            if let Node {
                id: node_id,
                wan_udp_addr: Some(peer_wan_addr),
                lan_udp_addr: Some(peer_lan_addr),
                ..
            } = dst_node
            {
                let direct_node_list: &HashSet<NodeId> = get_local_direct_node_list!();

                if direct_node_list.contains(node_id) {
                    let peer_addr = if interface_info.try_send_to_lan_addr {
                        match local_node.wan_udp_addr {
                            Some(local_wan_addr) if local_wan_addr.ip() == peer_wan_addr.ip() => {
                                *peer_lan_addr
                            }
                            _ => *peer_wan_addr,
                        }
                    } else {
                        *peer_wan_addr
                    };

                    let socket = match interface_info.udp_socket {
                        Some(ref v) => &**v,
                        None => unreachable!(),
                    };

                    let msg = UdpMsg::Data(data).encode(unsafe { &mut *buff });
                    interface_info.key.clone().encrypt_slice(msg);
                    socket.send_to(msg, peer_addr)?;
                    continue;
                }
            }
        }

        if local_node.mode.tcp_support() && dst_node.mode.tcp_support() {
            let tx = match interface_info.tcp_handler_channel {
                Some(ref v) => v,
                None => unreachable!(),
            };

            if let Err(TrySendError::Closed(_)) = tx.try_send((data.into(), dst_node.id)) {
                return Err(anyhow!("TCP handler channel closed"));
            }
        }
    }
}

fn udp_handler_inner<T: TunDevice>(
    tun: &T,
    socket: &UdpSocket,
    key: &Aes128Ctr,
    heartbeat_seq: &AtomicU32,
) -> Result<()> {
    let mut buff = vec![0u8; UDP_BUFF_SIZE];

    loop {
        let (len, peer_addr) = socket.recv_from(&mut buff)?;
        let packet = &mut buff[..len];
        key.clone().decrypt_slice(packet);

        if let Ok(packet) = UdpMsg::decode(packet) {
            match packet {
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Req)
                    if get_local_node_id() == node_id =>
                {
                    let resp = UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp);
                    let buff = resp.encode(&mut buff);
                    key.clone().encrypt_slice(buff);
                    socket.send_to(buff, peer_addr)?;
                }
                UdpMsg::Heartbeat(node_id, seq, HeartbeatType::Resp)
                    if node_id != get_local_node_id()
                        && seq == heartbeat_seq.load(Ordering::Relaxed) =>
                {
                    get_direct_node_list().try_update(node_id);
                }
                UdpMsg::Data(data) => tun.send_packet(data)?,
                _ => continue,
            }
        }
    }
}

fn heartbeat_schedule(seq: &AtomicU32) -> Result<()> {
    let mut buff = vec![0u8; get_config().mtu];
    init_interface_map!();

    loop {
        let interface_map: &HashMap<Ipv4Addr, InterfaceInfo<Arc<HashMap<Ipv4Addr, Node>>>> =
            get_local_interface_map!();
        let temp_seq = seq.load(Ordering::Relaxed);

        for (_, interface_info) in interface_map.iter() {
            let socket = match &interface_info.udp_socket {
                Some(socket) => &*socket,
                None => continue,
            };

            let msg = UdpMsg::Heartbeat(get_local_node_id(), temp_seq, HeartbeatType::Req);
            let out = msg.encode(&mut buff);
            interface_info.key.clone().encrypt_slice(out);

            if let Err(e) = socket.send_to(out, &interface_info.server_addr) {
                error!(
                    "UDP socket send to server {} error: {}",
                    &interface_info.server_addr, e
                )
            }

            for (local_addr, dest_node) in &*interface_info.node_map {
                if get_local_node_id() == dest_node.id {
                    continue;
                }

                if let Node {
                    id: node_id,
                    wan_udp_addr: Some(peer_wan_addr),
                    lan_udp_addr: Some(peer_lan_addr),
                    ..
                } = dest_node
                {
                    let dest_addr = if interface_info.try_send_to_lan_addr {
                        match interface_info.node_map.get(local_addr) {
                            Some(Node {
                                wan_udp_addr: Some(local_wan_addr),
                                ..
                            }) if local_wan_addr.ip() == peer_wan_addr.ip() => *peer_lan_addr,
                            _ => *peer_wan_addr,
                        }
                    } else {
                        *peer_wan_addr
                    };

                    let heartbeat_packet =
                        UdpMsg::Heartbeat(*node_id, temp_seq, HeartbeatType::Req);
                    let out = heartbeat_packet.encode(&mut buff);
                    interface_info.key.clone().encrypt_slice(out);
                    socket.send_to(out, dest_addr)?;
                }
            }
        }

        std::thread::sleep(get_config().udp_heartbeat_interval);
        seq.fetch_add(1, Ordering::Relaxed);
    }
}

async fn direct_node_list_schedule() {
    loop {
        time::sleep(Duration::from_secs(30)).await;
        let now = Utc::now().timestamp();
        let mut update = false;

        let new_map = {
            let guard = match get_direct_node_list().list.try_read() {
                Some(guard) => guard,
                None => continue,
            };

            let mut new = HashMap::with_capacity(guard.len());

            for (k, v) in guard.iter() {
                let time = v.load(Ordering::Relaxed);

                if now - time <= 30 {
                    new.insert(*k, AtomicI64::new(time));
                } else {
                    update = true
                }
            }
            new
        };

        if update {
            get_direct_node_list().try_update_all(new_map)
        }
    }
}

async fn udp_handler<T: TunDevice + 'static>(tun: Arc<T>) -> Result<()> {
    let map = get_interface_map();
    let seq = Arc::new(AtomicU32::new(0));

    let count = get_config().udp_handler_thread_count;
    let mut handle_list = Vec::with_capacity(map.map.len() * count);

    for (_, info) in map.map.iter() {
        for _ in 0..count {
            let socket = match info.udp_socket {
                Some(ref socket) => socket.clone(),
                None => continue,
            };

            let tun = tun.clone();
            let key = info.key.clone();
            let seq = seq.clone();

            let h = async {
                tokio::task::spawn_blocking(move || udp_handler_inner(&*tun, &*socket, &key, &*seq))
                    .await?
            };
            handle_list.push(h);
        }
    }

    let fut1 = async {
        futures_util::future::try_join_all(handle_list).await?;
        Ok(())
    };
    let fut2 = async { tokio::task::spawn_blocking(move || heartbeat_schedule(&*seq)).await? };
    let fut3 = async {
        tokio::spawn(direct_node_list_schedule()).await?;
        Ok(())
    };

    tokio::try_join!(fut1, fut2, fut3)?;
    Ok(())
}

async fn tcp_handler_inner(
    init_node: Node,
    mut from_tun: Option<Receiver<(Box<[u8]>, NodeId)>>,
    to_tun: Option<crossbeam_channel::Sender<Box<[u8]>>>,
    network_range_info: &NetworkRangeFinalize,
) {
    loop {
        let mut node = init_node.clone();
        node.register_time = Utc::now().timestamp();
        let inner_to_tun = &to_tun;
        let inner_from_tun = &mut from_tun;
        let mut tx_key = network_range_info.key.clone();
        let mut rx_key = network_range_info.key.clone();

        let process = async move {
            let mut stream = TcpStream::connect(&network_range_info.server_addr)
                .await
                .with_context(|| format!("Connect to {} error", &network_range_info.server_addr))?;

            let (rx, mut tx) = stream.split();
            let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);

            let mut msg_reader = TcpMsgReader::new(&mut rx, &mut rx_key);
            let mut msg_writer = TcpMsgWriter::new(&mut tx, &mut tx_key);

            let msg = TcpMsg::Register(node);
            msg_writer.write(&msg).await?;
            let msg = msg_reader.read().await?;

            match msg {
                TcpMsg::Result(MsgResult::Success) => (),
                TcpMsg::Result(MsgResult::Timeout) => {
                    return Err(anyhow!(
                        "{} register timeout",
                        &network_range_info.server_addr
                    ))
                }
                _ => {
                    return Err(anyhow!(
                        "{} register error",
                        &network_range_info.server_addr
                    ))
                }
            };

            info!("{} connected", &network_range_info.server_addr);

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
                            let mapping: HashMap<Ipv4Addr, Node> = node_map
                                .into_iter()
                                .map(|(_, node)| (node.tun_addr, node))
                                .collect();

                            get_interface_map().update(&network_range_info.tun.ip, mapping);
                        }
                        TcpMsg::Forward(packet, _) => {
                            if let Some(to_tun) = inner_to_tun {
                                to_tun.send(packet.into())?
                            }
                        }
                        TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                            let heartbeat = TcpMsg::Heartbeat(seq, HeartbeatType::Resp);
                            let res = tx.send(heartbeat).map_err(|e| anyhow!(e.to_string()));

                            if res.is_err() {
                                return res;
                            }
                        }
                        TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                            if inner_seq1.load(Ordering::Relaxed) == recv_seq {
                                latest_recv_heartbeat_time_ref1
                                    .store(Utc::now().timestamp(), Ordering::Relaxed)
                            }
                        }
                        _ => continue,
                    }
                }
            };

            let fut2 = async move {
                let mut heartbeat_interval = time::interval(get_config().tcp_heartbeat_interval);
                let mut check_heartbeat_timeout = time::interval(Duration::from_secs(30));

                loop {
                    tokio::select! {
                        opt = rx.recv() => {
                             match opt {
                                Some(heartbeat) => msg_writer.write(&heartbeat).await?,
                                None => return Ok(())
                            }
                        }
                        opt = match inner_from_tun {
                            Some(v) => v.recv().right_future(),
                            None => std::future::pending().left_future()
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
            error!(
                "TCP {} handler error -> {:?}",
                &network_range_info.server_addr, e
            )
        }

        time::sleep(get_config().reconnect_interval).await;
    }
}

fn mpsc_to_tun<T: TunDevice>(
    mpsc_rx: crossbeam_channel::Receiver<Box<[u8]>>,
    tun: &T,
) -> Result<()> {
    loop {
        let packet = mpsc_rx.recv()?;
        tun.send_packet(&packet)
            .context("Write packet to tun error")?;
    }
}

async fn tcp_handler<T: TunDevice + 'static>(
    mut map: HashMap<Ipv4Addr, (Option<Receiver<(Box<[u8]>, NodeId)>>, Node)>,
    tun: T,
) -> Result<()> {
    let mut handles = Vec::with_capacity(get_config().network_ranges.len());

    fn get_channel<T>() -> (
        Option<crossbeam_channel::Sender<T>>,
        Option<crossbeam_channel::Receiver<T>>,
    ) {
        for range in &get_config().network_ranges {
            if range.mode.tcp_support() {
                let (tx, rx) = crossbeam_channel::unbounded();
                return (Some(tx), Some(rx));
            }
        }
        (None, None)
    }

    let (to_tun, from_tcp_handler) = get_channel();

    for network_range in &get_config().network_ranges {
        let (from_tun, init_node) = match map.remove(&network_range.tun.ip) {
            Some(v) => v,
            None => unreachable!(),
        };

        let h = tokio::spawn(tcp_handler_inner(
            init_node,
            from_tun,
            to_tun.clone(),
            network_range,
        ));
        handles.push(h);
    }

    let fut1 = async {
        match from_tcp_handler {
            Some(rx) => tokio::task::spawn_blocking(move || mpsc_to_tun(rx, &tun)).await?,
            None => std::future::pending().await,
        }
    };

    let fut2 = async {
        futures_util::future::try_join_all(handles).await?;
        Ok(())
    };

    tokio::try_join!(fut1, fut2)?;
    Ok(())
}

pub(super) async fn start(config: ClientConfigFinalize) -> Result<()> {
    set_local_node_id(rand::random());
    set_config(config);

    let mut tcp_handler_initialize = HashMap::with_capacity(get_config().network_ranges.len());
    let mut interface_map_initialize = HashMap::with_capacity(get_config().network_ranges.len());
    let mut udp_support = false;

    for range in &get_config().network_ranges {
        if range.mode.udp_support() {
            udp_support = true;
        }

        let opt = match range.lan_ip_addr {
            Some(lan_ip_addr) if range.mode.udp_support() => {
                let udp_socket =
                    UdpSocket::bind((lan_ip_addr, 0)).context("Failed to create UDP socket")?;

                if let Some(v) = get_config().udp_socket_recv_buffer_size {
                    udp_socket.set_recv_buffer_size(v)?;
                }

                if let Some(v) = get_config().udp_socket_send_buffer_size {
                    udp_socket.set_send_buffer_size(v)?;
                }
                Some(udp_socket)
            }
            _ => None,
        };

        let (tx, rx) = if range.mode.tcp_support() {
            let (tx, rx) = tokio::sync::mpsc::channel(get_config().channel_limit);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let init_node = Node {
            id: get_local_node_id(),
            tun_addr: range.tun.ip,
            lan_udp_addr: match opt {
                Some(ref socket) => Some(socket.local_addr()?),
                None => None,
            },
            wan_udp_addr: None,
            mode: range.mode,
            register_time: 0,
        };

        tcp_handler_initialize.insert(range.tun.ip, (rx, init_node));

        let info = InterfaceInfo {
            node_map: (),
            server_addr: range.server_addr.clone(),
            tcp_handler_channel: tx,
            udp_socket: opt.map(Arc::new),
            key: range.key.clone(),
            try_send_to_lan_addr: range.try_send_to_lan_addr,
        };

        interface_map_initialize.insert(range.tun.ip, info);
    }

    set_interface_map(InterfaceMap::new(interface_map_initialize));
    set_direct_node_list(DirectNodeList::new());

    let tun_addrs: Vec<TunIpAddr> = get_config()
        .network_ranges
        .iter()
        .map(|range| range.tun.clone())
        .collect();

    let tun_device =
        create_device(get_config().mtu, &tun_addrs).context("Failed create tun adapter")?;
    let tun_device = Arc::new(tun_device);
    let inner_tun_device = tun_device.clone();

    let tun_handle = async {
        let count = get_config().tun_handler_thread_count;
        let mut handles = Vec::with_capacity(count);

        for _ in 0..count {
            let inner_tun_device = inner_tun_device.clone();
            let handle = async {
                tokio::task::spawn_blocking(move || tun_handler(&inner_tun_device)).await?
            };
            handles.push(handle)
        }

        futures_util::future::try_join_all(handles).await?;
        Ok(())
    };
    let tcp_handle = tcp_handler(tcp_handler_initialize, tun_device.clone());
    let udp_handle = if udp_support {
        udp_handler(tun_device).right_future()
    } else {
        std::future::pending().left_future()
    };
    let api_handle = async { tokio::spawn(api_start(get_config().api_addr)).await? };

    info!("Client start");
    tokio::try_join!(tun_handle, tcp_handle, udp_handle, api_handle)?;
    Ok(())
}
