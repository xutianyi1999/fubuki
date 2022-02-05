use std::borrow::Borrow;
use std::cell::{Cell, UnsafeCell};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use ahash::RandomState;
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
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;

use crate::{ClientConfig, TunConfig};
use crate::common::{HashMap, PointerWrap};
use crate::common::net::get_interface_addr;
use crate::common::net::msg_operator::{TCP_BUFF_SIZE, TcpMsgReader, TcpMsgWriter, UdpMsgSocket};
use crate::common::net::proto::{HeartbeatType, MsgResult, MTU, Node, NodeId, Seq, TcpMsg, UdpMsg};
use crate::common::net::proto::UdpMsg::Heartbeat;
use crate::common::persistence::ToJson;
use crate::tun::create_device;
use crate::tun::TunDevice;

const CHANNEL_SIZE: usize = 100;
static mut MAPPING: PointerWrap<NodeMapping> = PointerWrap::default();
static mut DIRECT_NODE_LIST: PointerWrap<DirectNodeList> = PointerWrap::default();

fn get_mapping() -> &'static NodeMapping {
    unsafe { &MAPPING }
}

fn get_direct_node_list() -> &'static DirectNodeList {
    unsafe { &DIRECT_NODE_LIST }
}

struct NodeMapping {
    // local_addr -> (tun_addr -> node)
    map: HashMap<
        Ipv4Addr,
        (RwLock<Arc<HashMap<Ipv4Addr, Node>>>, Rc4)
    >,
    version: AtomicU8,
}

impl NodeMapping {
    fn new(node_list: &[(Ipv4Addr, Rc4)]) -> Self {
        let map = node_list.iter()
            .map(|(tun_addr, rc4)| (*tun_addr, (RwLock::new(Arc::new(HashMap::default())), rc4.clone())))
            .collect();

        NodeMapping {
            map,
            version: AtomicU8::new(0),
        }
    }

    fn version(&self) -> u8 {
        self.version.load(Ordering::Relaxed)
    }

    fn update(&self, local_tun_addr: &Ipv4Addr, map: HashMap<Ipv4Addr, Node>) {
        let map = Arc::new(map);

        if let Some((lock, _)) = self.map.get(local_tun_addr) {
            *lock.write() = map;
            self.version.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn try_load(&self) -> Option<HashMap<
        Ipv4Addr,
        (Arc<HashMap<Ipv4Addr, Node>>, &Rc4)
    >> {
        let mut map = HashMap::default();

        for (k, (lock, rc4)) in &self.map {
            map.insert(*k, (lock.try_read()?.clone(), rc4));
        }
        Some(map)
    }
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

        get_direct_node_list().try_update_all(new_map)
    }
}

fn tun_handler<T: TunDevice>(
    tun: T,
    udp_socket_opt: Option<&UdpSocket>,
    tcp_tx_channel_map: HashMap<Ipv4Addr, Sender<(Box<[u8]>, NodeId)>>,
) -> Result<()> {
    let mut buff = [0u8; MTU];

    let mut local_node_mapping: HashMap<Ipv4Addr, Arc<HashMap<Ipv4Addr, Node>>> = HashMap::default();
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

        let mut peer_udp_socket_addr = Option::None;

        if udp_socket_opt.is_some() {
            let mapping: &HashMap<Ipv4Addr, Arc<HashMap<Ipv4Addr, Node>>> = get_local_node_mapping!();
            let mapping = match mapping.get(&src_addr) {
                Some(v) => &**v,
                None => continue
            };

            if let Some(
                Node {
                    id: node_id,
                    wan_udp_addr: Some(peer_wan_addr),
                    lan_udp_addr: Some(peer_lan_addr),
                    ..
                }
            ) = mapping.get(&dst_addr) {
                let direct_node_list: &HashSet<NodeId> = get_local_direct_node_list!();

                if direct_node_list.contains(node_id) {
                    let peer_addr = match mapping.get(&src_addr) {
                        Some(
                            Node { wan_udp_addr: Some(local_wan_addr), .. }
                        ) if local_wan_addr.ip() == peer_wan_addr.ip() => *peer_lan_addr,
                        _ => *peer_wan_addr
                    };
                    peer_udp_socket_addr = Some(peer_addr)
                }
            }
        }

        // if let Some(peer_addr) = peer_udp_socket_addr {
        //     let socket = match udp_socket_opt {
        //         None => unreachable!(),
        //         Some(v) => v
        //     };
        //     socket
        // }
    }
}

pub(super) async fn start(configs: Vec<ClientConfig>) -> Result<()> {
    let tun_configs: Vec<TunConfig> = configs.iter()
        .map(|v| v.tun.clone())
        .collect();

    let tun_device = create_device(tun_configs).context("Failed create tun adapter")?;
    let tun_device = Arc::new(tun_device);
    Ok(())
}