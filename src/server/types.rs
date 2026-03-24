use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use ahash::{HashMap, HashMapExt};
use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use crossbeam_utils::atomic::AtomicCell;
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::watch;

use crate::common::allocator::Bytes;
use crate::common::net::protocol::{Node, PeerStatus, VirtualAddr};
use crate::common::net::{FlowControl, HeartbeatCache, HeartbeatInfo, UdpStatus};
use crate::GroupFinalize;

pub type NodeMap = HashMap<VirtualAddr, Node>;


pub(crate) struct NodeHandle {
    pub(crate) node: ArcSwap<Node>,
    pub(crate) udp_status: AtomicCell<UdpStatus>,
    pub(crate) udp_heartbeat_cache: RwLock<HeartbeatCache>,
    pub(crate) tcp_heartbeat_cache: RwLock<HeartbeatCache>,
    // (peers, update time)
    pub(crate) peers_status: RwLock<Option<(Vec<PeerStatus>, Instant)>>,
    pub(crate) tx: Sender<Bytes>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct NodeInfo {
    pub(crate) node: Node,
    pub(crate) udp_status: UdpStatus,
    pub(crate) udp_heartbeat_cache: HeartbeatInfo,
    pub(crate) tcp_heartbeat_cache: HeartbeatInfo,
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

pub(crate) struct Bridge {
    pub(crate) channel_rx: Receiver<Bytes>,
    pub(crate) watch_rx: watch::Receiver<Arc<HashMap<VirtualAddr, Node>>>,
}

pub(crate) struct GroupHandle {
    pub(crate) name: String,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) address_range: Ipv4Net,
    pub(crate) limit: usize,
    pub(crate) mapping: RwLock<HashMap<VirtualAddr, Arc<NodeHandle>>>,
    pub(crate) watch: (watch::Sender<Arc<NodeMap>>, watch::Receiver<Arc<NodeMap>>),
    pub(crate) flow_control: FlowControl
}

impl GroupHandle {
    pub(crate) fn new<K>(
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
            flow_control: FlowControl::new(group_config.flow_control_rules.clone()),
        }
    }

    pub(crate) fn join(&self, node: Node) -> Result<(Bridge, Arc<NodeHandle>)> {
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
            peers_status: RwLock::new(None),
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

    pub(crate) fn sync(&self, node_map: &HashMap<VirtualAddr, Arc<NodeHandle>>) -> Result<()> {
        let (tx, _) = &self.watch;

        let node_list: HashMap<VirtualAddr, Node> = node_map
            .iter()
            .map(|(addr, handle)| (*addr, (**handle.node.load()).clone()))
            .collect();

        tx.send(Arc::new(node_list))
            .map_err(|_| anyhow!("Failed to synchronize node map. The watch channel might be closed."))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GroupInfo {
    pub(crate) name: String,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) address_range: Ipv4Net,
    pub(crate) node_map: HashMap<VirtualAddr, NodeInfo>,
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
