use ahash::HashMap;
use std::cell::SyncUnsafeCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption, Cache};
use crossbeam_utils::atomic::AtomicCell;
use ipnet::Ipv4Net;
use linear_map::LinearMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

use crate::common::allocator::Bytes;
use crate::common::net::protocol::{Node, PeerStatus, VirtualAddr};
use crate::common::net::{HeartbeatCache, HeartbeatInfo, UdpStatus};
use crate::ProtocolMode;

pub(crate) type NodeList = Vec<ExtendedNode>;

pub(crate) trait NodeListOps {
    fn get_node(&self, addr: &VirtualAddr) -> Option<&ExtendedNode>;
}

impl NodeListOps for NodeList {
    fn get_node(&self, addr: &VirtualAddr) -> Option<&ExtendedNode> {
        self.binary_search_by_key(addr, |node| node.node.virtual_addr)
            .ok()
            .map(|v| &self[v])
    }
}

pub(crate) enum RoutingTableEnum<A, B> {
    Internal(ArcSwap<A>),
    External(SyncUnsafeCell<B>)
}

pub(crate) enum RoutingTableRefEnum<'a, A, B> {
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

pub(crate) struct AtomicAddr {
    inner: AtomicU32
}

impl AtomicAddr {
    pub(crate) fn load(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.inner.load(Ordering::Relaxed))
    }

    pub(crate) fn store(&self, addr: Ipv4Addr) {
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

pub(crate) struct AtomicCidr {
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
    pub(crate) fn load(&self) -> Ipv4Net {
        let inner: Inner = unsafe {
            std::mem::transmute(self.inner.load(Ordering::Relaxed))
        };
        inner.v
    }

    pub(crate) fn store(&self, cidr: Ipv4Net) {
        let v: u64 = unsafe {
            std::mem::transmute(Inner { v: cidr })
        };

        self.inner.store(v, Ordering::Relaxed)
    }
}

pub struct Interface<K> {
    pub(crate) index: usize,
    pub(crate) node_name: String,
    pub(crate) group_name: ArcSwapOption<String>,
    pub(crate) addr: AtomicAddr,
    pub(crate) cidr: AtomicCidr,
    pub(crate) mode: ProtocolMode,
    pub(crate) specify_mode: LinearMap<VirtualAddr, ProtocolMode>,
    pub(crate) node_list: ArcSwap<NodeList>,
    pub(crate) server_addr: String,
    pub(crate) server_udp_hc: RwLock<HeartbeatCache>,
    pub(crate) server_udp_status: AtomicCell<UdpStatus>,
    pub(crate) server_tcp_hc: RwLock<HeartbeatCache>,
    pub(crate) server_is_connected: AtomicBool,
    pub(crate) server_allow_udp_relay: AtomicBool,
    pub(crate) server_allow_tcp_relay: AtomicBool,
    pub(crate) tcp_handler_channel: Option<Sender<Bytes>>,
    pub(crate) udp_socket: Option<UdpSocket>,
    pub(crate) key: K,
    pub(crate) peers_map: Option<RwLock<HashMap<VirtualAddr, Vec<PeerStatus>>>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InterfaceInfo {
    pub(crate) index: usize,
    pub(crate) node_name: String,
    pub(crate) group_name: Option<String>,
    pub(crate) addr: VirtualAddr,
    pub(crate) cidr: Ipv4Net,
    pub(crate) mode: ProtocolMode,
    pub(crate) node_map: HashMap<VirtualAddr, ExtendedNodeInfo>,
    pub(crate) server_addr: String,
    pub(crate) server_udp_hc: HeartbeatInfo,
    pub(crate) server_udp_status: UdpStatus,
    pub(crate) server_tcp_hc: HeartbeatInfo,
    pub(crate) server_is_connected: bool,
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

pub(crate) struct ExtendedNode {
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
pub(crate) struct ExtendedNodeInfo {
    pub(crate) node: Node,
    pub(crate) udp_status: UdpStatus,
    pub(crate) hc: HeartbeatInfo,
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


#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Output,
    Input
}
